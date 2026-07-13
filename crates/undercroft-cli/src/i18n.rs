//! CLI output localization.
//!
//! Scope (documented in docs/PARITY.md): the high-traffic *result* strings
//! a person reads after a command — init, vault creation, filing, mining /
//! sweeping / importing summaries, empty search results, and the verify
//! verdicts. Errors, help text, and machine-oriented output (exit codes,
//! JSONL, MCP) stay English; scripts should key off exit codes, not prose.
//!
//! Language selection: `UNDERCROFT_LANG`, falling back to `LANG`, reduced to
//! its primary subtag (`pt_BR.UTF-8` → `pt`). Unknown languages fall back
//! to English, and English templates are byte-identical to the historical
//! output, so nothing changes unless a user opts in. The nine translated
//! languages mirror the model_eval dataset languages: de, es, fr, hi, it,
//! ko, pt, ru, zh.

/// Resolve the active language code.
fn lang() -> String {
    let raw = std::env::var("UNDERCROFT_LANG")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    raw.split(['_', '-', '.'])
        .next()
        .unwrap_or("")
        .to_lowercase()
}

/// Translate a message key into the active language's template.
pub fn tr(key: &str) -> &'static str {
    let l = lang();
    lookup(&l, key).unwrap_or_else(|| lookup("en", key).expect("every key has an en template"))
}

/// Fill `{name}` placeholders in a template.
pub fn fill(template: &str, pairs: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (k, v) in pairs {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

macro_rules! msg {
    ($v:expr) => {
        Some($v)
    };
}

fn lookup(lang: &str, key: &str) -> Option<&'static str> {
    match (lang, key) {
        // ------------------------------------------------------- English
        ("en", "palace-initialized") => msg!("Palace initialized at {path}"),
        ("en", "palace-already") => msg!("Palace already initialized at {path}"),
        ("en", "vault-created") => msg!("Created vault '{name}' (level: {level})"),
        ("en", "drawer-filed") => msg!("Filed drawer {id} in {wing}/{room} (vault '{vault}')"),
        ("en", "no-matches") => msg!("No memories matched."),
        ("en", "verify-ok") => msg!("VERIFY OK"),
        ("en", "verify-failed") => msg!("VERIFY FAILED"),
        ("en", "mined-summary") => msg!(
            "Mined {files} file(s) into vault '{vault}' wing '{wing}': {drawers} drawer(s) filed"
        ),
        ("en", "swept-summary") => msg!(
            "Swept {files} transcript(s): {filed} message drawer(s) filed, {skipped} already present"
        ),
        ("en", "imported-summary") => msg!(
            "Imported {n} drawer(s) into vault '{vault}' ({skipped} duplicates skipped)"
        ),
        // ------------------------------------------------------- Deutsch
        ("de", "palace-initialized") => msg!("Palast initialisiert unter {path}"),
        ("de", "palace-already") => msg!("Palast bereits initialisiert unter {path}"),
        ("de", "vault-created") => msg!("Tresor '{name}' erstellt (Stufe: {level})"),
        ("de", "drawer-filed") => {
            msg!("Schublade {id} in {wing}/{room} abgelegt (Tresor '{vault}')")
        }
        ("de", "no-matches") => msg!("Keine Erinnerungen gefunden."),
        ("de", "verify-ok") => msg!("PRÜFUNG OK"),
        ("de", "verify-failed") => msg!("PRÜFUNG FEHLGESCHLAGEN"),
        ("de", "mined-summary") => msg!(
            "{files} Datei(en) in Tresor '{vault}', Flügel '{wing}' eingelesen: {drawers} Schublade(n) abgelegt"
        ),
        ("de", "swept-summary") => msg!(
            "{files} Transkript(e) durchsucht: {filed} Nachrichten-Schublade(n) abgelegt, {skipped} bereits vorhanden"
        ),
        ("de", "imported-summary") => msg!(
            "{n} Schublade(n) in Tresor '{vault}' importiert ({skipped} Duplikate übersprungen)"
        ),
        // ------------------------------------------------------- Español
        ("es", "palace-initialized") => msg!("Palacio inicializado en {path}"),
        ("es", "palace-already") => msg!("El palacio ya está inicializado en {path}"),
        ("es", "vault-created") => msg!("Bóveda '{name}' creada (nivel: {level})"),
        ("es", "drawer-filed") => {
            msg!("Cajón {id} archivado en {wing}/{room} (bóveda '{vault}')")
        }
        ("es", "no-matches") => msg!("Ninguna memoria coincidió."),
        ("es", "verify-ok") => msg!("VERIFICACIÓN OK"),
        ("es", "verify-failed") => msg!("VERIFICACIÓN FALLIDA"),
        ("es", "mined-summary") => msg!(
            "{files} archivo(s) minados en la bóveda '{vault}', ala '{wing}': {drawers} cajón(es) archivados"
        ),
        ("es", "swept-summary") => msg!(
            "{files} transcripción(es) barridas: {filed} cajón(es) de mensajes archivados, {skipped} ya presentes"
        ),
        ("es", "imported-summary") => msg!(
            "{n} cajón(es) importados a la bóveda '{vault}' ({skipped} duplicados omitidos)"
        ),
        // ------------------------------------------------------ Français
        ("fr", "palace-initialized") => msg!("Palais initialisé dans {path}"),
        ("fr", "palace-already") => msg!("Palais déjà initialisé dans {path}"),
        ("fr", "vault-created") => msg!("Coffre '{name}' créé (niveau : {level})"),
        ("fr", "drawer-filed") => {
            msg!("Tiroir {id} classé dans {wing}/{room} (coffre '{vault}')")
        }
        ("fr", "no-matches") => msg!("Aucun souvenir trouvé."),
        ("fr", "verify-ok") => msg!("VÉRIFICATION OK"),
        ("fr", "verify-failed") => msg!("ÉCHEC DE LA VÉRIFICATION"),
        ("fr", "mined-summary") => msg!(
            "{files} fichier(s) extraits vers le coffre '{vault}', aile '{wing}' : {drawers} tiroir(s) classés"
        ),
        ("fr", "swept-summary") => msg!(
            "{files} transcription(s) balayées : {filed} tiroir(s) de messages classés, {skipped} déjà présents"
        ),
        ("fr", "imported-summary") => msg!(
            "{n} tiroir(s) importés dans le coffre '{vault}' ({skipped} doublons ignorés)"
        ),
        // ------------------------------------------------------ Italiano
        ("it", "palace-initialized") => msg!("Palazzo inizializzato in {path}"),
        ("it", "palace-already") => msg!("Palazzo già inizializzato in {path}"),
        ("it", "vault-created") => msg!("Cassaforte '{name}' creata (livello: {level})"),
        ("it", "drawer-filed") => {
            msg!("Cassetto {id} archiviato in {wing}/{room} (cassaforte '{vault}')")
        }
        ("it", "no-matches") => msg!("Nessuna memoria trovata."),
        ("it", "verify-ok") => msg!("VERIFICA OK"),
        ("it", "verify-failed") => msg!("VERIFICA FALLITA"),
        ("it", "mined-summary") => msg!(
            "{files} file estratti nella cassaforte '{vault}', ala '{wing}': {drawers} cassetto/i archiviati"
        ),
        ("it", "swept-summary") => msg!(
            "{files} trascrizione/i esaminate: {filed} cassetto/i di messaggi archiviati, {skipped} già presenti"
        ),
        ("it", "imported-summary") => msg!(
            "{n} cassetto/i importati nella cassaforte '{vault}' ({skipped} duplicati saltati)"
        ),
        // ----------------------------------------------------- Português
        ("pt", "palace-initialized") => msg!("Palácio inicializado em {path}"),
        ("pt", "palace-already") => msg!("Palácio já inicializado em {path}"),
        ("pt", "vault-created") => msg!("Cofre '{name}' criado (nível: {level})"),
        ("pt", "drawer-filed") => {
            msg!("Gaveta {id} arquivada em {wing}/{room} (cofre '{vault}')")
        }
        ("pt", "no-matches") => msg!("Nenhuma memória encontrada."),
        ("pt", "verify-ok") => msg!("VERIFICAÇÃO OK"),
        ("pt", "verify-failed") => msg!("FALHA NA VERIFICAÇÃO"),
        ("pt", "mined-summary") => msg!(
            "{files} arquivo(s) minerados no cofre '{vault}', ala '{wing}': {drawers} gaveta(s) arquivadas"
        ),
        ("pt", "swept-summary") => msg!(
            "{files} transcrição(ões) varridas: {filed} gaveta(s) de mensagens arquivadas, {skipped} já presentes"
        ),
        ("pt", "imported-summary") => msg!(
            "{n} gaveta(s) importadas para o cofre '{vault}' ({skipped} duplicatas ignoradas)"
        ),
        // ------------------------------------------------------- Русский
        ("ru", "palace-initialized") => msg!("Дворец инициализирован в {path}"),
        ("ru", "palace-already") => msg!("Дворец уже инициализирован в {path}"),
        ("ru", "vault-created") => msg!("Хранилище '{name}' создано (уровень: {level})"),
        ("ru", "drawer-filed") => {
            msg!("Ящик {id} сохранён в {wing}/{room} (хранилище '{vault}')")
        }
        ("ru", "no-matches") => msg!("Воспоминаний не найдено."),
        ("ru", "verify-ok") => msg!("ПРОВЕРКА ПРОЙДЕНА"),
        ("ru", "verify-failed") => msg!("ПРОВЕРКА НЕ ПРОЙДЕНА"),
        ("ru", "mined-summary") => msg!(
            "Файлов обработано: {files}; в хранилище '{vault}', крыло '{wing}' добавлено ящиков: {drawers}"
        ),
        ("ru", "swept-summary") => msg!(
            "Транскриптов просмотрено: {files}; сохранено ящиков-сообщений: {filed}, уже имелось: {skipped}"
        ),
        ("ru", "imported-summary") => msg!(
            "Импортировано ящиков в хранилище '{vault}': {n} (пропущено дубликатов: {skipped})"
        ),
        // -------------------------------------------------------- 中文
        ("zh", "palace-initialized") => msg!("记忆宫殿已在 {path} 初始化"),
        ("zh", "palace-already") => msg!("记忆宫殿已存在于 {path}"),
        ("zh", "vault-created") => msg!("已创建保险库 '{name}'（级别：{level}）"),
        ("zh", "drawer-filed") => {
            msg!("抽屉 {id} 已归档到 {wing}/{room}（保险库 '{vault}'）")
        }
        ("zh", "no-matches") => msg!("没有匹配的记忆。"),
        ("zh", "verify-ok") => msg!("校验通过"),
        ("zh", "verify-failed") => msg!("校验失败"),
        ("zh", "mined-summary") => msg!(
            "已挖掘 {files} 个文件到保险库 '{vault}' 的 '{wing}' 翼：归档 {drawers} 个抽屉"
        ),
        ("zh", "swept-summary") => msg!(
            "已扫描 {files} 份对话记录：归档 {filed} 条消息抽屉，{skipped} 条已存在"
        ),
        ("zh", "imported-summary") => msg!(
            "已向保险库 '{vault}' 导入 {n} 个抽屉（跳过 {skipped} 个重复项）"
        ),
        // ------------------------------------------------------- 한국어
        ("ko", "palace-initialized") => msg!("궁전이 {path} 에 초기화되었습니다"),
        ("ko", "palace-already") => msg!("궁전이 이미 {path} 에 초기화되어 있습니다"),
        ("ko", "vault-created") => msg!("금고 '{name}' 생성됨 (등급: {level})"),
        ("ko", "drawer-filed") => {
            msg!("서랍 {id} 이(가) {wing}/{room} 에 보관되었습니다 (금고 '{vault}')")
        }
        ("ko", "no-matches") => msg!("일치하는 기억이 없습니다."),
        ("ko", "verify-ok") => msg!("검증 통과"),
        ("ko", "verify-failed") => msg!("검증 실패"),
        ("ko", "mined-summary") => msg!(
            "파일 {files}개를 금고 '{vault}' 의 '{wing}' 동에 채굴: 서랍 {drawers}개 보관"
        ),
        ("ko", "swept-summary") => msg!(
            "대화 기록 {files}건 스캔: 메시지 서랍 {filed}개 보관, {skipped}개는 이미 존재"
        ),
        ("ko", "imported-summary") => msg!(
            "금고 '{vault}' 로 서랍 {n}개 가져옴 (중복 {skipped}개 건너뜀)"
        ),
        // -------------------------------------------------------- हिन्दी
        ("hi", "palace-initialized") => msg!("महल {path} पर आरंभ किया गया"),
        ("hi", "palace-already") => msg!("महल पहले से {path} पर आरंभ है"),
        ("hi", "vault-created") => msg!("तिजोरी '{name}' बनाई गई (स्तर: {level})"),
        ("hi", "drawer-filed") => {
            msg!("दराज {id} को {wing}/{room} में रखा गया (तिजोरी '{vault}')")
        }
        ("hi", "no-matches") => msg!("कोई स्मृति नहीं मिली।"),
        ("hi", "verify-ok") => msg!("सत्यापन सफल"),
        ("hi", "verify-failed") => msg!("सत्यापन विफल"),
        ("hi", "mined-summary") => msg!(
            "{files} फ़ाइलें तिजोरी '{vault}' के '{wing}' खंड में जोड़ी गईं: {drawers} दराज रखे गए"
        ),
        ("hi", "swept-summary") => msg!(
            "{files} प्रतिलेख स्कैन किए गए: {filed} संदेश-दराज रखे गए, {skipped} पहले से मौजूद"
        ),
        ("hi", "imported-summary") => msg!(
            "तिजोरी '{vault}' में {n} दराज आयात किए गए ({skipped} डुप्लिकेट छोड़े गए)"
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &[&str] = &[
        "palace-initialized",
        "palace-already",
        "vault-created",
        "drawer-filed",
        "no-matches",
        "verify-ok",
        "verify-failed",
        "mined-summary",
        "swept-summary",
        "imported-summary",
    ];
    const LANGS: &[&str] = &["en", "de", "es", "fr", "it", "pt", "ru", "zh", "ko", "hi"];

    #[test]
    fn every_language_covers_every_key() {
        for l in LANGS {
            for k in KEYS {
                assert!(lookup(l, k).is_some(), "missing {l}/{k}");
            }
        }
    }

    #[test]
    fn placeholders_survive_translation() {
        // Every placeholder in the English template must appear in each
        // translation — a dropped placeholder silently loses data.
        for k in KEYS {
            let en = lookup("en", k).unwrap();
            let placeholders: Vec<&str> = en
                .match_indices('{')
                .map(|(i, _)| &en[i..=en[i..].find('}').unwrap() + i])
                .collect();
            for l in LANGS {
                let t = lookup(l, k).unwrap();
                for p in &placeholders {
                    assert!(t.contains(p), "{l}/{k} lost placeholder {p}");
                }
            }
        }
    }

    #[test]
    fn fill_replaces_named_placeholders() {
        let out = fill(
            "Filed drawer {id} in {wing}/{room} (vault '{vault}')",
            &[
                ("id", "abc".into()),
                ("wing", "w".into()),
                ("room", "r".into()),
                ("vault", "v".into()),
            ],
        );
        assert_eq!(out, "Filed drawer abc in w/r (vault 'v')");
    }
}
