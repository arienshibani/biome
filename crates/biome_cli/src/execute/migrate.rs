mod eslint;
mod eslint_any_rule_to_biome;
mod eslint_jsxa11y;
mod eslint_typescript;
mod eslint_unicorn;
mod prettier;

use crate::commands::MigrateSubCommand;
use crate::diagnostics::MigrationDiagnostic;
use crate::execute::diagnostics::{ContentDiffAdvice, MigrateDiffDiagnostic};
use crate::execute::migrate::prettier::read_prettier_files;
use crate::{CliDiagnostic, CliSession};
use biome_console::{markup, ConsoleExt};
use biome_deserialize::json::deserialize_from_json_str;
use biome_deserialize::Merge;
use biome_diagnostics::{category, PrintDiagnostic};
use biome_diagnostics::{Diagnostic, DiagnosticExt};
use biome_fs::{BiomePath, ConfigName, FileSystemExt, OpenOptions};
use biome_json_parser::{parse_json_with_cache, JsonParserOptions};
use biome_json_syntax::{JsonFileSource, JsonRoot};
use biome_migrate::{migrate_configuration, ControlFlow};
use biome_rowan::{AstNode, NodeCache};
use biome_service::workspace::{ChangeFileParams, FixAction, FormatFileParams, OpenFileParams};
use biome_service::{PartialConfiguration, VERSION};
use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

pub(crate) struct MigratePayload<'a> {
    pub(crate) session: CliSession<'a>,
    pub(crate) write: bool,
    pub(crate) configuration_file_path: PathBuf,
    pub(crate) configuration_directory_path: PathBuf,
    pub(crate) verbose: bool,
    pub(crate) sub_command: Option<MigrateSubCommand>,
}

pub(crate) fn run(migrate_payload: MigratePayload) -> Result<(), CliDiagnostic> {
    let MigratePayload {
        session,
        write,
        configuration_file_path,
        configuration_directory_path,
        verbose,
        sub_command,
    } = migrate_payload;
    let mut cache = NodeCache::default();
    let fs = &session.app.fs;
    let console = session.app.console;
    let workspace = session.app.workspace;

    let has_deprecated_configuration =
        configuration_file_path.file_name() == Some(OsStr::new("rome.json"));

    let open_options = if write {
        OpenOptions::default().read(true).write(true)
    } else {
        OpenOptions::default().read(true)
    };

    let mut biome_config_file =
        fs.open_with_options(configuration_file_path.as_path(), open_options)?;
    let mut biome_config_content = String::new();
    biome_config_file.read_to_string(&mut biome_config_content)?;

    let biome_path = BiomePath::new(configuration_file_path.as_path());
    workspace.open_file(OpenFileParams {
        path: biome_path.clone(),
        content: biome_config_content.to_string(),
        version: 0,
        document_file_source: Some(JsonFileSource::json().into()),
    })?;

    let parsed = parse_json_with_cache(
        &biome_config_content,
        &mut cache,
        JsonParserOptions::default(),
    );

    let mut errors = 0;
    let mut tree = parsed.tree();
    let mut actions = Vec::new();
    loop {
        let (action, _) = migrate_configuration(
            &tree,
            configuration_file_path.as_path(),
            VERSION.to_string(),
            |signal| {
                let current_diagnostic = signal.diagnostic();
                if current_diagnostic.is_some() {
                    errors += 1;
                }

                if let Some(action) = signal.actions().next() {
                    return ControlFlow::Break(action);
                }

                ControlFlow::Continue(())
            },
        );

        match action {
            Some(action) => {
                if let Some((range, _)) = action.mutation.as_text_edits() {
                    tree = match JsonRoot::cast(action.mutation.commit()) {
                        Some(tree) => tree,
                        None => return Err(CliDiagnostic::check_error(category!("migrate"))),
                    };
                    actions.push(FixAction {
                        rule_name: action
                            .rule_name
                            .map(|(group, rule)| (Cow::Borrowed(group), Cow::Borrowed(rule))),
                        range,
                    });
                }
            }
            None => {
                break;
            }
        }
    }

    let new_configuration_content = tree.to_string();

    match sub_command {
        Some(MigrateSubCommand::Prettier) => {
            let prettier_configuration = read_prettier_files(fs, console)?;

            if prettier_configuration.has_configuration() {
                let biome_config = deserialize_from_json_str::<PartialConfiguration>(
                    biome_config_content.as_str(),
                    JsonParserOptions::default(),
                    "",
                )
                .into_deserialized();
                if let Some(mut biome_config) = biome_config {
                    biome_config.merge_with(prettier_configuration.as_biome_configuration());

                    let new_content = serde_json::to_string(&biome_config).map_err(|err| {
                        CliDiagnostic::MigrateError(MigrationDiagnostic {
                            reason: err.to_string(),
                        })
                    })?;

                    workspace.change_file(ChangeFileParams {
                        path: biome_path.clone(),
                        content: new_content,
                        version: 1,
                    })?;

                    let printed = workspace.format_file(FormatFileParams { path: biome_path })?;

                    if write {
                        biome_config_file.set_content(printed.as_code().as_bytes())?;
                        console.log(markup!{
                            <Info>"The configuration "<Emphasis>{{configuration_file_path.display().to_string()}}</Emphasis>" has been successfully migrated."</Info>
                        });
                        if prettier_configuration.has_ignore_file() {
                            console.log(markup!{
                                <Warn>"Please make sure that the globs of the "<Emphasis>".prettierignore"</Emphasis>" file still work in Biome. Prettier's globs use git globs, while Biome's globs use uni-style globs. They both seem similar, but their semantics differ."</Warn>
                            })
                        }
                    } else {
                        let file_name = configuration_file_path.display().to_string();
                        let diagnostic = MigrateDiffDiagnostic {
                            file_name,
                            diff: ContentDiffAdvice {
                                old: biome_config_content,
                                new: printed.as_code().to_string(),
                            },
                        };
                        console.error(markup! {{PrintDiagnostic::simple(&diagnostic)}});

                        console.log(markup! {
                            "Run the command with the option "<Emphasis>"--write"</Emphasis>" to apply the changes."
                        })
                    }
                }
            }
        }
        Some(MigrateSubCommand::Eslint {
            include_inspired,
            include_nursery,
            eslint_config,
        }) => {
            let eslint_path_str = eslint_config.to_string_lossy();
            /*if let Some(eslint_conf_ext) = eslint_config.extension().and_then(|ext| ext.to_str()) {
                match eslint_conf_ext {
                    "json" => {
                        let content = fs::read_to_string(&eslint_config)?;
                        let deserialized = deserialize_from_json_str::<eslint::ConfigData>(
                            &output,
                            JsonParserOptions::default()
                                .with_allow_trailing_commas()
                                .with_allow_comments(),
                            &eslint_path_str,
                        );
                    }
                    "js" | "cjs" | "mjs" => {
                        let output = Command::new("node")
                            .arg("--eval")
                            .arg(format!("import('{eslint_path_str}').then((c) => console.log(c.default))"))
                            .output()?;
                    }
                    _ => {}
                }
            }
            if eslint_config_extension.is_some_and(|extension| extension == "json") {
                let deserialized = deserialize_from_json_str::<eslint::ConfigData>(
                    &output,
                    JsonParserOptions::default()
                        .with_allow_trailing_commas()
                        .with_allow_comments(),
                    &eslint_path_str,
                );
            }*/
            let output = Command::new("npx")
                .arg("eslint")
                .arg("--config")
                .arg(format!("{}", eslint_path_str))
                .arg("--print-config")
                .arg("file.js")
                .output()?;
            let output = String::from_utf8_lossy(&output.stdout);
            let deserialized = deserialize_from_json_str::<eslint::ConfigData>(
                &output,
                JsonParserOptions::default()
                    .with_allow_trailing_commas()
                    .with_allow_comments(),
                &eslint_path_str,
            );
            if deserialized.has_errors() {
                let diagnostics = deserialized.into_diagnostics();
                for diagnostic in diagnostics {
                    let diagnostic = diagnostic.with_file_path(eslint_path_str.to_string());
                    console.error(markup! {{PrintDiagnostic::simple(&diagnostic)}});
                }
                return Err(CliDiagnostic::MigrateError(MigrationDiagnostic {
                    reason: "Could not deserialize the Eslint configuration file".to_string(),
                }));
            } else if let Some(eslint_config) = deserialized.into_deserialized() {
                let biome_config = deserialize_from_json_str::<PartialConfiguration>(
                    biome_config_content.as_str(),
                    JsonParserOptions::default(),
                    "",
                )
                .into_deserialized();
                if let Some(mut biome_config) = biome_config {
                    let (biome_eslint_config, results) =
                        eslint_config.into_biome_config(&eslint::MigrationOptions {
                            include_inspired,
                            include_nursery,
                        });
                    biome_config.merge_with(biome_eslint_config);
                    let new_content = serde_json::to_string(&biome_config).map_err(|err| {
                        CliDiagnostic::MigrateError(MigrationDiagnostic {
                            reason: err.to_string(),
                        })
                    })?;
                    workspace.change_file(ChangeFileParams {
                        path: biome_path.clone(),
                        content: new_content,
                        version: 1,
                    })?;
                    let printed = workspace.format_file(FormatFileParams { path: biome_path })?;
                    if write {
                        biome_config_file.set_content(printed.as_code().as_bytes())?;
                        let mut output = String::new();
                        for rule_name in results.migrated_rules {
                            output.push_str(rule_name);
                            output.push('\n');
                        }
                        console.log(markup! {
                            <Info>
                                <Emphasis>"Migrated rules:"</Emphasis>"\n"
                                { output }
                            </Info>
                        });
                        console.log(markup!{
                        <Info>"The configuration "<Emphasis>{{configuration_file_path.display().to_string()}}</Emphasis>" has been successfully migrated."</Info>
                    });
                    } else {
                        let file_name = configuration_file_path.display().to_string();
                        let diagnostic = MigrateDiffDiagnostic {
                            file_name,
                            diff: ContentDiffAdvice {
                                old: biome_config_content,
                                new: printed.as_code().to_string(),
                            },
                        };
                        console.error(markup! {{PrintDiagnostic::simple(&diagnostic)}});
                        console.log(markup! {
                        "Run the command with the option "<Emphasis>"--write"</Emphasis>" to apply the changes."
                    })
                    }
                }
            }
        }
        None => {
            if biome_config_content != new_configuration_content || has_deprecated_configuration {
                if write {
                    let mut configuration_file = if has_deprecated_configuration {
                        let biome_file_path =
                            configuration_directory_path.join(ConfigName::biome_json());
                        fs.create_new(biome_file_path.as_path())?
                    } else {
                        biome_config_file
                    };
                    configuration_file.set_content(tree.to_string().as_bytes())?;
                    console.log(markup!{
                            <Info>"The configuration "<Emphasis>{{configuration_file_path.display().to_string()}}</Emphasis>" has been successfully migrated."</Info>
                        })
                } else {
                    let file_name = configuration_file_path.display().to_string();
                    let diagnostic = if has_deprecated_configuration {
                        MigrateDiffDiagnostic {
                            file_name,
                            diff: ContentDiffAdvice {
                                old: "rome.json".to_string(),
                                new: "biome.json".to_string(),
                            },
                        }
                    } else {
                        MigrateDiffDiagnostic {
                            file_name,
                            diff: ContentDiffAdvice {
                                old: biome_config_content,
                                new: new_configuration_content,
                            },
                        }
                    };
                    if diagnostic.tags().is_verbose() {
                        if verbose {
                            console.error(markup! {{PrintDiagnostic::verbose(&diagnostic)}})
                        }
                    } else {
                        console.error(markup! {{PrintDiagnostic::simple(&diagnostic)}})
                    }
                    console.log(markup! {
                            "Run the command with the option "<Emphasis>"--write"</Emphasis>" to apply the changes."
                        })
                }
            } else {
                console.log(markup! {
                    <Info>
                    "Your configuration file is up to date."
                    </Info>
                })
            }
        }
    }

    Ok(())
}
