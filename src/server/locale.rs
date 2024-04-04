use poem::i18n::I18NResources;

pub fn resources() -> I18NResources {
    I18NResources::builder()
        .add_ftl("en_US", include_str!("../../locales/en_US/simple.ftl"))
        .build()
        .unwrap()
}
