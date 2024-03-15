/// This modules includes implementations for deserializing an eslint configuration
/// and convert it to Biome's configuration.
///
/// The conversion relies on:
/// - the generated [super::eslint_any_rule_to_biome::migrate_eslint_any_rule]
///   module that relies on Biome's rule metadata to determine
///   the equivalent Biome's rule of an Eslint rule
/// - hand-written handling of Biome rules that have options in the current module.
use std::{any::TypeId, marker::PhantomData, ops::Deref, vec::IntoIter};

use biome_deserialize::StringSet;
use biome_deserialize::{
    Deserializable, DeserializableValue, DeserializationDiagnostic, DeserializationVisitor,
    VisitableType,
};
use biome_deserialize_macros::Deserializable;
use biome_js_analyze::semantic_analyzers::style::no_restricted_globals;
use biome_rowan::TextRange;
use biome_service::configuration as biome;
use biome_service::configuration::linter::RulePlainConfiguration;
use rustc_hash::FxHashMap;

use super::eslint_any_rule_to_biome::migrate_eslint_any_rule;
use super::{eslint_jsxa11y, eslint_typescript, eslint_unicorn};

#[derive(Debug)]
pub(crate) struct MigrationOptions {
    /// Migrate inspired rules from eslint and its plugins?
    pub(crate) include_inspired: bool,
    /// Migrate nursery rules from eslint and its plugins?
    pub(crate) include_nursery: bool,
}

#[derive(Debug, Default)]
pub(crate) struct MigrationResults {
    // Rules that were successfuly migrated
    pub(crate) migrated_rules: Vec<&'static str>,
    // Rules that have no equivalent in Biome
    pub(crate) unsupported_rules: Vec<String>,
    // Inspired rules that were not migrated because `include_inspired` is disabled
    pub(crate) inspired_rules: Vec<&'static str>,
    // Nursery rules that were not migrated because `include_nursery` is disabled
    pub(crate) nursery_rules: Vec<&'static str>,
}

// The following types corresponds to Eslint's config shape.
// See https://github.com/eslint/eslint/blob/ce838adc3b673e52a151f36da0eedf5876977514/lib/shared/types.js

#[derive(Debug, Default, Deserializable)]
#[deserializable(unknown_fields = "allow")]
pub(crate) struct ConfigData {
    pub(crate) extends: Shorthand<String>,
    pub(crate) env: FxHashMap<String, bool>,
    pub(crate) globals: FxHashMap<String, GlobalConf>,
    /// The glob patterns that ignore to lint.
    pub(crate) ignore_patterns: Shorthand<String>,
    /// The parser options.
    pub(crate) rules: Rules,
    pub(crate) overrides: Vec<OverrideConfigData>,
}
impl ConfigData {
    pub(crate) fn into_biome_config(
        self,
        options: &MigrationOptions,
    ) -> (biome::PartialConfiguration, MigrationResults) {
        let mut results = MigrationResults::default();
        let mut biome_config = biome::PartialConfiguration::default();
        if !self.globals.is_empty() {
            let globals = self
                .globals
                .into_iter()
                .filter_map(|(global_name, global_conf)| {
                    global_conf.is_enabled().then_some(global_name)
                })
                .collect::<StringSet>();
            let js_config = biome::PartialJavascriptConfiguration {
                globals: Some(globals),
                ..Default::default()
            };
            biome_config.javascript = Some(js_config)
        }
        let mut linter = biome::PartialLinterConfiguration::default();
        if !self.ignore_patterns.is_empty() {
            let ignore = self.ignore_patterns.into_iter().collect::<StringSet>();
            linter.ignore = Some(ignore);
        }
        if !self.rules.is_empty() {
            linter.rules = Some(self.rules.into_biome_rules(options, &mut results));
        }
        if !self.overrides.is_empty() {
            let mut overrides = biome::Overrides::default();
            for override_elt in self.overrides {
                let mut override_pattern = biome::OverridePattern::default();
                if !override_elt.globals.is_empty() {
                    let globals = override_elt.globals.into_keys().collect::<StringSet>();
                    let js_config = biome::PartialJavascriptConfiguration {
                        globals: Some(globals),
                        ..Default::default()
                    };
                    override_pattern.javascript = Some(js_config)
                }
                if !override_elt.excluded_files.is_empty() {
                    override_pattern.ignore =
                        Some(override_elt.excluded_files.into_iter().collect());
                }
                if !override_elt.files.is_empty() {
                    override_pattern.ignore = Some(override_elt.files.into_iter().collect());
                }
                if !override_elt.rules.is_empty() {
                    linter.rules = Some(override_elt.rules.into_biome_rules(options, &mut results));
                }
                overrides.0.push(override_pattern);
            }
            biome_config.overrides = Some(overrides);
        }
        biome_config.linter = Some(linter);
        (biome_config, results)
    }
}

#[derive(Debug)]
pub(crate) enum GlobalConf {
    Flag(bool),
    Qualifier(GlobalConfQualifier),
}
impl GlobalConf {
    pub(crate) fn is_enabled(&self) -> bool {
        match self {
            GlobalConf::Flag(result) => *result,
            GlobalConf::Qualifier(qualifier) => !matches!(qualifier, GlobalConfQualifier::Off),
        }
    }
}
impl Deserializable for GlobalConf {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        if value.is_type(VisitableType::STR) {
            Deserializable::deserialize(value, name, diagnostics).map(Self::Qualifier)
        } else {
            Deserializable::deserialize(value, name, diagnostics).map(Self::Flag)
        }
    }
}

#[derive(Debug, Deserializable)]
pub(crate) enum GlobalConfQualifier {
    Off,
    Readable,
    Readonly,
    Writable,
    Writeable,
}

#[derive(Debug, Default, Deserializable)]
#[deserializable(unknown_fields = "allow")]
pub(crate) struct OverrideConfigData {
    pub(crate) extends: Shorthand<String>,
    pub(crate) env: FxHashMap<String, bool>,
    pub(crate) globals: FxHashMap<String, GlobalConf>,
    /// The glob patterns for excluded files.
    pub(crate) excluded_files: Shorthand<String>,
    /// The glob patterns for target files.
    pub(crate) files: Shorthand<String>,
    pub(crate) rules: Rules,
}

#[derive(Debug, Default)]
pub(crate) struct Shorthand<T>(Vec<T>);
impl<T> From<T> for Shorthand<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}
impl<T> Deref for Shorthand<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> IntoIterator for Shorthand<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl<T: Deserializable> Deserializable for Shorthand<T> {
    fn deserialize(
        value: &impl DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<DeserializationDiagnostic>,
    ) -> Option<Self> {
        Some(Shorthand(if value.is_type(VisitableType::ARRAY) {
            Deserializable::deserialize(value, name, diagnostics)?
        } else {
            Vec::from_iter([Deserializable::deserialize(value, name, diagnostics)?])
        }))
    }
}

#[derive(Debug)]
pub(crate) enum RuleConf<T = (), U = ()> {
    Severity(Severity),
    Option(Severity, T),
    Options(Severity, T, U),
    Spread(Severity, Vec<T>),
}
impl<T, U> RuleConf<T, U> {
    pub(crate) fn severity(&self) -> Severity {
        match self {
            Self::Severity(severity) => *severity,
            Self::Option(severity, _) => *severity,
            Self::Options(severity, _, _) => *severity,
            Self::Spread(severity, _) => *severity,
        }
    }
}
impl<T> RuleConf<T, ()> {
    fn into_vec(self) -> Vec<T> {
        match self {
            RuleConf::Severity(_) => vec![],
            RuleConf::Option(_, value) | RuleConf::Options(_, value, _) => vec![value],
            RuleConf::Spread(_, result) => result,
        }
    }
}
impl<T: Default, U: Default> RuleConf<T, U> {
    fn option_or_default(self) -> T {
        match self {
            RuleConf::Severity(_) | RuleConf::Options(_, _, _) | RuleConf::Spread(_, _) => {
                T::default()
            }
            RuleConf::Option(_, option) => option,
        }
    }
}
impl<T: Deserializable + 'static, U: Deserializable + 'static> Deserializable for RuleConf<T, U> {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        struct Visitor<T, U>(PhantomData<(T, U)>);
        impl<T: Deserializable + 'static, U: Deserializable + 'static> DeserializationVisitor
            for Visitor<T, U>
        {
            type Output = RuleConf<T, U>;
            const EXPECTED_TYPE: VisitableType = VisitableType::ARRAY;
            fn visit_array(
                self,
                values: impl Iterator<Item = Option<impl DeserializableValue>>,
                range: TextRange,
                _name: &str,
                diagnostics: &mut Vec<DeserializationDiagnostic>,
            ) -> Option<Self::Output> {
                let mut values = values.flatten();
                let Some(first_value) = values.next() else {
                    diagnostics.push(
                        DeserializationDiagnostic::new("A severity is expected.").with_range(range),
                    );
                    return None;
                };
                let severity = Deserializable::deserialize(&first_value, "", diagnostics)?;
                if TypeId::of::<T>() == TypeId::of::<()>() {
                    return Some(RuleConf::Severity(severity));
                }
                let Some(second_value) = values.next() else {
                    return Some(RuleConf::Severity(severity));
                };
                let Some(option) = T::deserialize(&second_value, "", diagnostics) else {
                    // Recover by ignoring the failed deserialization
                    return Some(RuleConf::Severity(severity));
                };
                let Some(third_value) = values.next() else {
                    return Some(RuleConf::Option(severity, option));
                };
                if TypeId::of::<U>() != TypeId::of::<()>() {
                    if let Some(option2) = U::deserialize(&third_value, "", diagnostics) {
                        return Some(RuleConf::Options(severity, option, option2));
                    } else {
                        // Recover by ignoring the failed deserialization
                        return Some(RuleConf::Option(severity, option));
                    }
                }
                let Some(option2) = T::deserialize(&third_value, "", diagnostics) else {
                    // Recover by ignoring the failed deserialization
                    return Some(RuleConf::Option(severity, option));
                };
                let mut spread = Vec::new();
                spread.push(option);
                spread.push(option2);
                spread.extend(values.filter_map(|val| T::deserialize(&val, "", diagnostics)));
                Some(RuleConf::Spread(severity, spread))
            }
        }
        if value.is_type(VisitableType::NUMBER) {
            Deserializable::deserialize(value, name, diagnostics).map(RuleConf::Severity)
        } else {
            value.deserialize(Visitor(PhantomData), name, diagnostics)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserializable)]
#[deserializable(try_from = "NumberOrString")]
pub(crate) enum Severity {
    Off,
    Warn,
    Error,
}
impl TryFrom<NumberOrString> for Severity {
    type Error = &'static str;

    fn try_from(value: NumberOrString) -> Result<Self, &'static str> {
        match value {
            NumberOrString::Number(n) => match n {
                0 => Ok(Severity::Off),
                1 => Ok(Severity::Warn),
                2 => Ok(Severity::Error),
                _ => Err("Severity should be 0, 1 or 2."),
            },
            NumberOrString::String(s) => match s.as_ref() {
                "off" => Ok(Severity::Off),
                "warn" => Ok(Severity::Warn),
                "error" => Ok(Severity::Error),
                _ => Err("Severity should be 'off', 'warn' or 'error'."),
            },
        }
    }
}
impl From<Severity> for RulePlainConfiguration {
    fn from(value: Severity) -> RulePlainConfiguration {
        match value {
            Severity::Off => RulePlainConfiguration::Off,
            Severity::Warn => RulePlainConfiguration::Warn,
            Severity::Error => RulePlainConfiguration::Error,
        }
    }
}
#[derive(Debug)]
enum NumberOrString {
    Number(u64),
    String(String),
}
impl Deserializable for NumberOrString {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        Some(if value.is_type(VisitableType::STR) {
            Self::String(Deserializable::deserialize(value, name, diagnostics)?)
        } else {
            Self::Number(Deserializable::deserialize(value, name, diagnostics)?)
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct Rules(pub(crate) Vec<Rule>);
impl IntoIterator for Rules {
    type Item = Rule;
    type IntoIter = IntoIter<Rule>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl Deref for Rules {
    type Target = Vec<Rule>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Deserializable for Rules {
    fn deserialize(
        value: &impl biome_deserialize::DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
    ) -> Option<Self> {
        struct Visitor;
        impl DeserializationVisitor for Visitor {
            type Output = Rules;
            const EXPECTED_TYPE: VisitableType = VisitableType::MAP;
            fn visit_map(
                self,
                members: impl Iterator<
                    Item = Option<(
                        impl biome_deserialize::DeserializableValue,
                        impl biome_deserialize::DeserializableValue,
                    )>,
                >,
                _range: biome_rowan::TextRange,
                name: &str,
                diagnostics: &mut Vec<biome_deserialize::DeserializationDiagnostic>,
            ) -> Option<Self::Output> {
                use biome_deserialize::Text;
                let mut result = Vec::new();
                for (key, value) in members.flatten() {
                    let Some(rule_name) = Text::deserialize(&key, "", diagnostics) else {
                        continue;
                    };
                    match rule_name.text() {
                        // Eslint rules with options that we handle
                        "no-restricted-globals" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.push(Rule::NoRestrictedGlobals(conf))
                            }
                        }
                        // Eslint plugin rules with options that we handle
                        "jsx-a11y/aria-role" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.push(Rule::Jsxa11yArioaRoles(conf))
                            }
                        }
                        "@typescript-eslint/array-type" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.push(Rule::TypeScriptArrayType(conf))
                            }
                        }
                        "@typescript-eslint/naming-convention" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.push(Rule::TypeScriptNamingConvention(conf))
                            }
                        }
                        "unicorn/filename-case" => {
                            if let Some(conf) = RuleConf::deserialize(&value, name, diagnostics) {
                                result.push(Rule::UnicornFilenameCase(conf))
                            }
                        }
                        // Other rules
                        rule_name => {
                            if let Some(conf) =
                                RuleConf::<()>::deserialize(&value, name, diagnostics)
                            {
                                result.push(Rule::Any {
                                    name: rule_name.to_string(),
                                    severity: conf.severity(),
                                })
                            }
                        }
                    }
                }
                Some(Rules(result))
            }
        }
        value.deserialize(Visitor, name, diagnostics)
    }
}
impl Rules {
    pub(crate) fn into_biome_rules(
        self,
        options: &MigrationOptions,
        results: &mut MigrationResults,
    ) -> biome::Rules {
        let mut rules = biome::Rules::default();
        for eslint_rule in self {
            migrate_eslint_rule(&mut rules, eslint_rule, options, results);
        }
        rules
    }
}

#[derive(Debug)]
pub(crate) enum NoRestrictedGlobal {
    Plain(String),
    WithMessage(GlobalWithMessage),
}
impl NoRestrictedGlobal {
    fn into_name(self) -> String {
        match self {
            NoRestrictedGlobal::Plain(name) => name,
            NoRestrictedGlobal::WithMessage(named) => named.name,
        }
    }
}
impl Deserializable for NoRestrictedGlobal {
    fn deserialize(
        value: &impl DeserializableValue,
        name: &str,
        diagnostics: &mut Vec<DeserializationDiagnostic>,
    ) -> Option<Self> {
        if value.is_type(VisitableType::STR) {
            Deserializable::deserialize(value, name, diagnostics).map(NoRestrictedGlobal::Plain)
        } else {
            Deserializable::deserialize(value, name, diagnostics)
                .map(NoRestrictedGlobal::WithMessage)
        }
    }
}
#[derive(Debug, Default, Deserializable)]
pub(crate) struct GlobalWithMessage {
    name: String,
    message: String,
}

#[derive(Debug)]
pub(crate) enum Rule {
    /// Any rule without its options.
    Any {
        name: String,
        severity: Severity,
    },
    // Eslint rules with its options
    // We use this to configure equivalent Bione's rules.
    NoRestrictedGlobals(RuleConf<NoRestrictedGlobal>),
    // Eslint plugins
    Jsxa11yArioaRoles(RuleConf<eslint_jsxa11y::AriaRoleOptions>),
    TypeScriptArrayType(RuleConf<eslint_typescript::ArrayTypeOptions>),
    TypeScriptNamingConvention(RuleConf<Box<eslint_typescript::NamingConventionSelection>>),
    UnicornFilenameCase(RuleConf<eslint_unicorn::FilenameCaseOptions>),
}

/// Look for an equivalent Biome rule for ESlint `rule`,
/// and then mutate `rules` if a equivalent rule is found.
/// Also, takes care of Biome's rules with options.
fn migrate_eslint_rule(
    rules: &mut biome_service::Rules,
    rule: Rule,
    opts: &MigrationOptions,
    results: &mut MigrationResults,
) {
    match rule {
        Rule::Any { name, severity } => {
            let _ = migrate_eslint_any_rule(rules, &name, severity, opts, results);
        }
        Rule::NoRestrictedGlobals(conf) => {
            let name = "no-restricted-globals";
            if migrate_eslint_any_rule(rules, name, conf.severity(), opts, results) {
                let severity = conf.severity();
                let globals = conf.into_vec().into_iter().map(|g| g.into_name());
                let group = rules.style.get_or_insert_with(Default::default);
                group.no_restricted_globals = Some(biome_service::RuleConfiguration::WithOptions(
                    biome_service::RuleWithOptions {
                        level: severity.into(),
                        options: Box::new(no_restricted_globals::RestrictedGlobalsOptions {
                            denied_globals: globals.collect(),
                        }),
                    },
                ));
            }
        }
        Rule::Jsxa11yArioaRoles(conf) => {
            let name = "jsx-a11y/aria-role";
            if migrate_eslint_any_rule(rules, name, conf.severity(), opts, results) {
                if let RuleConf::Option(severity, rule_options) = conf {
                    let group = rules.a11y.get_or_insert_with(Default::default);
                    group.use_valid_aria_role =
                        Some(biome_service::RuleConfiguration::WithOptions(
                            biome_service::RuleWithOptions {
                                level: severity.into(),
                                options: Box::new(rule_options.into()),
                            },
                        ));
                }
            }
        }
        Rule::TypeScriptArrayType(conf) => {
            let name = "@typescript-eslint/array-type";
            if migrate_eslint_any_rule(rules, name, conf.severity(), opts, results) {
                if let RuleConf::Option(severity, rule_options) = conf {
                    let group = rules.style.get_or_insert_with(Default::default);
                    group.use_consistent_array_type =
                        Some(biome_service::RuleConfiguration::WithOptions(
                            biome_service::RuleWithOptions {
                                level: severity.into(),
                                options: rule_options.into(),
                            },
                        ));
                }
            }
        }
        Rule::TypeScriptNamingConvention(conf) => {
            let name = "@typescript-eslint/naming_convention";
            if migrate_eslint_any_rule(rules, name, conf.severity(), opts, results) {
                let severity = conf.severity();
                let options = eslint_typescript::NamingConventionOptions::override_default(
                    conf.into_vec().into_iter().map(|v| *v),
                );
                let group = rules.style.get_or_insert_with(Default::default);
                group.use_naming_convention = Some(biome_service::RuleConfiguration::WithOptions(
                    biome_service::RuleWithOptions {
                        level: severity.into(),
                        options: options.into(),
                    },
                ));
            }
        }
        Rule::UnicornFilenameCase(conf) => {
            let name = "unicorn/filename-case";
            if migrate_eslint_any_rule(rules, name, conf.severity(), opts, results) {
                let group = rules.style.get_or_insert_with(Default::default);
                group.use_filenaming_convention = Some(
                    biome_service::RuleConfiguration::WithOptions(biome_service::RuleWithOptions {
                        level: conf.severity().into(),
                        options: Box::new(conf.option_or_default().into()),
                    }),
                );
            }
        }
    }
}
