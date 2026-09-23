use std::collections::HashMap;
use std::sync::LazyLock;

/// Comprehensive WHOIS server list.
/// Data sourced from https://github.com/WooMai/whois-servers (auto-synced with IANA Root Zone Database).
///
/// Intentional omissions
/// ---------------------
/// Google Registry / Charleston Road Registry TLDs (app, dev, page, google,
/// new, how, ads, android, chrome, docs, drive, gmail, youtube, etc. — every
/// TLD historically mapped to `whois.nic.google`) are *not* in this map.
/// `whois.nic.google` does not resolve and IANA publishes no `whois:` field
/// for these TLDs; they are RDAP-only. Re-adding them sends every WHOIS
/// query to a dead hostname and produces a misleading "DNS resolution failed"
/// instead of the clean `WhoisServerNotFound` error the discovery path
/// generates. Use `seer.lookup()` (RDAP-first) or `seer.rdap_domain()` for
/// these TLDs.
///
/// For the same reason, these TLDs were removed 2026-07-04 after a full-TLD
/// live sweep found their WHOIS hostnames dead in DNS and their IANA records
/// no longer publishing a `whois:` field (RDAP-only transitions): `apple`,
/// `brussels`, `cymru`, `wales`, `vlaanderen`, `pharmacy`, `na`, `xn--p1acf`
/// (+ its `рус` alias); second wave same day from a ccTLD follow-up audit:
/// `lk` (+ `xn--fzc2c9e2c`/`ලංකා`, `xn--xkc2al3hye2a`/`இலங்கை`) and `mt`.
/// Do not re-add any of them from stale upstream lists without re-checking
/// IANA (`whois -h whois.iana.org <tld>`).
///
/// Conversely, two entries here deliberately DISAGREE with IANA (live-probed
/// 2026-07-04): `ga` → `whois.nic.ga` (ANINF runs port-43 but IANA lists no
/// server, Freenom aftermath) and `ps` → `whois.registry.ps` (PNINA
/// relocated; IANA still lists the dead `whois.pnina.ps`).
///
/// Last upstream sync: 2026-08-07. Delta applied: CONAC's two gTLDs moved off
/// the shared `whois.conac.cn` host to per-TLD servers (`xn--55qw42g`/公益 →
/// `whois.nic.xn--55qw42g`, `xn--zfr164b`/政务 → `whois.nic.xn--zfr164b`;
/// IANA records changed 2026-07-21, both hostnames verified in DNS). Every
/// retired TLD above was re-checked against IANA the same day: all still
/// publish an empty `whois:` field, so the upstream entries for them remain
/// stale and none were re-added.
///
/// Second-level registry zones (e.g. ZACR's `co.za`) live in
/// [`SLD_WHOIS_SERVERS`] below, resolved domain-first via
/// [`get_whois_server_for_domain`].
///
/// Built from the tables below: [`NIC_TLDS`] (served at the conventional
/// `whois.nic.<tld>` host), [`HOSTED_TLDS`] (every other TLD, grouped by
/// host) and [`IDN_ALIASES`] (U-labels keyed under their A-label's server).
pub static WHOIS_SERVERS: LazyLock<HashMap<&'static str, String>> = LazyLock::new(|| {
    let mut m: HashMap<&'static str, String> = NIC_TLDS
        .split_ascii_whitespace()
        .map(|tld| (tld, format!("whois.nic.{tld}")))
        .collect();
    for (host, tlds) in HOSTED_TLDS {
        for tld in tlds.split_ascii_whitespace() {
            m.insert(tld, host.to_string());
        }
    }
    // After the A-labels are in: each U-label takes its A-label's server, so
    // the two forms of an IDN TLD cannot drift apart.
    for alias in IDN_ALIASES.split_ascii_whitespace() {
        let server = crate::validation::domain_to_ascii(alias)
            .ok()
            .and_then(|ascii| m.get(ascii.as_str()).cloned());
        if let Some(server) = server {
            m.insert(alias, server);
        }
    }
    m
});

/// TLDs whose registry answers at the conventional `whois.nic.<tld>` host
/// (gTLDs, ccTLDs and IDN A-labels alike). Whitespace-separated, sorted.
const NIC_TLDS: &str = "
    aaa aarp abb abbott abbvie abc abogado abudhabi ac academy accenture accountant accountants aco
    actor ad adult aeg af afl africa ag agakhan agency ai airbus airforce airtel akdn alibaba alipay
    allfinanz allstate ally alsace alstom amazon americanfamily amfam amsterdam anz aol apartments
    aquarelle ar arab archi army art arte as asda asia associates at attorney auction audi audible
    audio auspost author auto autos aw aws azure baby band bank bar barcelona barclaycard barclays
    barefoot bargains baseball basketball bauhaus bayern bbc bbt bbva bcg bcn beats beauty beer
    berlin best bestbuy bet bh bharti bible bid bike bing bingo bio biz bj black blackfriday
    blockbuster blog bloomberg blue bm bms bmw bnpparibas bo boats boehringer bofa bond book bosch
    bostik boston bot boutique box bradesco bridgestone broadway broker brother build builders
    business buy buzz bzh cab cafe call cam camera camp canon capetown capital capitalone car cards
    care career careers cars casa case cash casino cat catering catholic cba cd center ceo cern cfa
    cfd ch chanel charity chat cheap chintai christmas church ci cipriani circle citadel city cl
    claims cleaning clinic clinique clothing cloud club clubmed cm coach codes coffee college
    commbank community company compare computer comsec condos construction consulting contact
    contractors cooking cool coop corsica coupon coupons courses cpa cr credit creditcard
    creditunion cricket crown crs cruise cruises cuisinella cv cx cyou cz dance data date dating dds
    deal dealer deals degree delivery deloitte delta democrat dental dentist desi design diamonds
    diet digital direct directory discount discover dish dnp do doctor dog domains dot download dtv
    dubai durban dvag dvr dz earth ec eco edeka education email emerck energy engineer engineering
    enterprises epson equipment ericsson erni es estate eurovision eus events exchange expert
    exposed express extraspace fage fail fairwinds faith family fan fans farm fashion fast fedex
    ferrari fidelity fido film finance financial fire firestone firmdale fish fishing fit fitness
    flights florist flowers fm fo football forex forsale foundation fox fr free fresenius frl
    frogans fun fund furniture futbol fyi ga gal gallery gallo gallup game games garden gay gd gdn
    ge gea gent genting george ggee gh gifts gives giving gl glass global gmbh gmo gmx godaddy gold
    goldpoint golf goodyear gop got gov gp graphics gratis green gripe grocery group gs gucci guide
    guitars guru hair hamburg haus hdfc hdfcbank healthcare help helsinki hermes hiphop hkt hn
    hockey holdings holiday homedepot homes honda horse hospital host hosting hot hotels hotmail
    house ht hu hughes hyundai ibm icbc ice icu ifm ikano im imamat imdb immo immobilien inc
    industries info ink institute insurance insure international investments io ir irish ismaili ist
    istanbul it itv jaguar java jeep jetzt jewelry jio jll jobs joburg jot joy jprs juniper kaufen
    kddi kerryhotels kerryproperties kfh ki kia kids kim kindle kitchen kiwi kn komatsu kosher krd
    kuokgroup kw kyoto kz la lacaixa lamborghini lamer land landrover lasalle lat latino latrobe law
    lawyer lds lease leclerc lefrak legal lego lexus lgbt li lidl life lifeinsurance lighting like
    limited limo live llc llp loan loans locker locus lol london lotte lotto love lpl lplfinancial
    ls ltd ltda lundbeck luxe luxury lv ly madrid maif maison makeup man management mango market
    marketing markets marriott mba mc mckinsey md me med media melbourne memorial men menu merck
    merckmsd mg miami microsoft mini mit ml mls mma mn mobi mobile moda moe moi mom monash money
    monster mormon mortgage moscow moto motorcycles movie mr ms msd mtn mtr museum mw mz nab nagoya
    name navy nec netbank network news next nextdirect nf ngo nhk nico nikon ninja nissay nokia
    norton now nowruz nowtv nra nrw ntt nyc obi observer office okinawa olayan olayangroup ollo
    omega one ong onl online ooo open oracle orange organic origins osaka otsuka ott ovh paris pars
    partners parts party pay pccw pet pg philips phone photo photography photos physio pics pictet
    pictures pin ping pink pioneer pizza place playstation plumbing plus pm pnc pohl poker politie
    porn post press prime pro productions progressive promo properties protection pub pw pwc qpon
    quebec quest racing radio re read realestate realtor realty recipes red redumbrella rehab reise
    reisen reit reliance ren rent rentals repair report republican rest restaurant review reviews
    rexroth rich richardli ricoh ril rip rocks rodeo rogers room rugby ruhr run rwe ryukyu saarland
    safe safety sakura sale salon samsclub samsung sandvik sandvikcoromant sanofi sap sarl save saxo
    sbi sbs sc scb schmidt scholarships school schule schwarz science scot sd seat secure security
    seek select services seven sew sex sfr sh shangrila shell shia shiksha shoes shop shopping show
    silk sina singles site ski skin sky skype sl sling sm smart smile sn sncf so soccer social
    softbank software solar solutions song sony spa space sport spot srl ss st stada star statebank
    stc stcgroup stockholm storage store stream studio study style sucks supplies supply support
    surf surgery suzuki swatch swiss sydney systems tab taipei talk taobao tatamotors tatar tattoo
    tax taxi tc tci td tdk team tech technology tel temasek tennis teva tf tg thd theater theatre
    tiaa tickets tienda tips tires tirol tl tm tmall today tokyo tools top toray toshiba total tours
    town toyota toys trade trading training travel travelers travelersinsurance trv tube tui tunes
    tushu tv tvs ubank ubs uk unicom university uno ups us vacations vanguard ve vegas ventures
    verisign versicherung vet vg viajes video vig viking villas vin vip virgin visa vision viva
    vodka volvo vote voting voto voyage walmart walter wanggou watch watches webcam weber website
    wed wedding weibo weir wf whoswho wien wiki win windows wine wme woodside work works world wow
    wtc wtf xbox xerox xin xn--11b4c3d xn--1ck2e1b xn--3pxu8k xn--42c2d9a xn--4gbrim xn--55qw42g
    xn--5su34j936bgsg xn--5tzm5g xn--6frz82g xn--80adxhks xn--80aqecdr1a xn--80asehdb xn--80aswg
    xn--8y0a063a xn--9dbq2a xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c xn--c1avg xn--c2br7g
    xn--cck2b3b xn--cckwcxetd xn--czrs0t xn--d1acj3b xn--eckvdtc9d xn--fct429k xn--fhbei xn--fjq720a
    xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gk3at1e xn--i1b6b1a6a2e xn--j1aef xn--jlq480n2rg
    xn--jvr189m xn--kcrx77d1x4a xn--kput3i xn--mgba7c0bbn0a xn--mgbab2bd xn--mgbca7dzdo
    xn--mgbi4ecexp xn--mgbt3dhd xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx
    xn--nqv7f xn--nqv7fs00ema xn--pssy2u xn--rovu88b xn--ses554g xn--t60b56a xn--tckwe xn--tiq49xqyj
    xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb xn--vhquv xn--w4r85el8fhu5dnra
    xn--w4rs40l xn--zfr164b xxx xyz yachts yahoo yamaxun yandex yoga yokohama you yt zappos zara
    zero zone zuerich
";

/// Every other TLD, grouped by the WHOIS host that serves it:
/// `(host, whitespace-separated TLDs)`. Sorted by host.
const HOSTED_TLDS: &[(&str, &str)] = &[
    ("ccwhois.verisign-grs.com", "cc"),
    ("kero.yachay.pe", "pe"),
    ("virgil.nic.vi", "vi"),
    ("whois.aeda.net.ae", "ae xn--mgbaam7a8h"),
    ("whois.aero", "aero"),
    ("whois.afilias-grs.info", "bz lc"),
    ("whois.afilias-srs.net", "pr schaeffler"),
    ("whois.amnic.net", "am xn--y9a3aq"),
    ("whois.ande.gov.gn", "gn"),
    ("whois.ati.tn", "tn xn--pgbs0dh"),
    ("whois.auda.org.au", "au"),
    ("whois.ax", "ax"),
    ("whois.bnnic.bn", "bn"),
    ("whois.cctld.by", "by xn--90ais"),
    ("whois.cctld.uz", "uz"),
    ("whois.cira.ca", "ca"),
    ("whois.cmc.iq", "iq xn--mgbtx2b"),
    ("whois.cnnic.cn", "cn xn--fiqs8s xn--fiqz9s"),
    ("whois.co.ug", "ug"),
    ("whois.denic.de", "de"),
    ("whois.dmdomains.dm", "dm"),
    ("whois.dnrs.vu", "vu"),
    ("whois.dns.be", "be"),
    ("whois.dns.hr", "hr"),
    ("whois.dns.lu", "lu"),
    ("whois.dns.pl", "pl"),
    ("whois.dns.pt", "pt"),
    ("whois.domain-registry.nl", "nl"),
    ("whois.dominio.gq", "gq"),
    ("whois.domreg.lt", "lt"),
    ("whois.dot.cf", "cf"),
    ("whois.dot.tk", "tk"),
    ("whois.dotmasr.eg", "xn--wgbh1c"),
    ("whois.dotukr.com", "xn--j1amh"),
    ("whois.educause.edu", "edu"),
    ("whois.eu", "eu xn--e1a4c xn--qxa6a"),
    ("whois.fi", "fi"),
    ("whois.gg", "gg"),
    ("whois.gtld.knet.cn", "baidu"),
    (
        "whois.gtld.zdns.cn",
        "wang xn--30rr7y xn--3bst00m xn--45q11c xn--6qq986b3xl xn--9et52u xn--czru2d xn--efvy88h
         xn--fiq64b xn--hxt814e",
    ),
    ("whois.gtlds.nic.br", "bom final globo rio uol"),
    ("whois.hkirc.hk", "hk xn--j6w193g"),
    ("whois.iana.org", "arpa int"),
    ("whois.id", "id"),
    ("whois.identitydigital.services", "gi vc"),
    ("whois.iis.nu", "nu"),
    ("whois.iis.se", "se"),
    ("whois.imena.bg", "xn--90ae"),
    ("whois.irs.net.nz", "nz"),
    ("whois.isnic.is", "is"),
    ("whois.isoc.org.il", "il xn--4dbrk0ce"),
    ("whois.je", "je"),
    ("whois.jprs.jp", "jp"),
    ("whois.kenic.or.ke", "ke"),
    ("whois.kg", "kg"),
    ("whois.kr", "kr xn--3e0b707e xn--cg4bki"),
    ("whois.kyregistry.ky", "ky"),
    ("whois.lbdr.org.lb", "lb"),
    ("whois.marnet.mk", "mk xn--d1alf"),
    ("whois.mediaserv.net", "gf mq"),
    ("whois.mn", "xn--l1acc"),
    ("whois.monic.mo", "mo xn--mix891f"),
    ("whois.mx", "mx"),
    ("whois.mynic.my", "my xn--mgbx4cd0ab"),
    ("whois.nc", "nc"),
    (
        "whois.ngtld.cn",
        "xn--1qqw23a xn--55qx5d xn--io0a7i xn--xhq521b",
    ),
    ("whois.nic.dz", "xn--lgbbat1ad8j"),
    (
        "whois.nic.gmo",
        "datsun fujitsu hisamitsu hitachi infiniti jcb mitsubishi nissan panasonic sharp yodobashi",
    ),
    ("whois.nic.ir", "xn--mgba3a4f16a"),
    ("whois.nic.kz", "xn--80ao21a"),
    ("whois.nic.la", "xn--q7ce6a"),
    ("whois.nic.mr", "xn--mgbah1a3hjkrd"),
    ("whois.nic.net.bw", "bw"),
    ("whois.nic.net.ng", "ng"),
    ("whois.nic.net.sa", "sa xn--mgberp4a5d4ar"),
    ("whois.nic.net.sb", "sb"),
    ("whois.nic.org.uy", "uy"),
    ("whois.nic.rwe", "sener"),
    (
        "whois.nixiregistry.in",
        "in xn--2scrj9c xn--3hcrj9c xn--45br5cyl xn--45brj9c xn--fpcrj9c3d xn--gecrj9c
         xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--mgbbh1a xn--mgbbh1a71e xn--mgbgu82a
         xn--rvc1e0am3e xn--s9brj9c xn--xkc2dl3a5ee0h",
    ),
    ("whois.norid.no", "no"),
    ("whois.pknic.net.pk", "pk"),
    ("whois.publicinterestregistry.org", "org"),
    ("whois.punktum.dk", "dk"),
    ("whois.register.bg", "bg"),
    ("whois.register.si", "si"),
    ("whois.registre.bf", "bf"),
    ("whois.registre.ma", "ma"),
    ("whois.registro.br", "br"),
    (
        "whois.registry.click",
        "click country diy feedback food forum hiv lifestyle living pid property sexy trust vana",
    ),
    ("whois.registry.co", "co"),
    ("whois.registry.gift", "gift"),
    ("whois.registry.gov.mm", "mm"),
    ("whois.registry.gy", "gy"),
    ("whois.registry.hm", "hm"),
    ("whois.registry.om", "om xn--mgb9awbf"),
    ("whois.registry.pf", "pf"),
    ("whois.registry.ps", "ps xn--ygbi2ammx"),
    ("whois.registry.qa", "qa xn--wgbl6a"),
    ("whois.registryservices.music", "music"),
    ("whois.ricta.org.rw", "rw"),
    ("whois.rnids.rs", "rs xn--90a3ac"),
    ("whois.rotld.ro", "ro"),
    ("whois.ryce-rsp.com", "cologne koeln"),
    ("whois.sgnic.sg", "sg"),
    ("whois.sk-nic.sk", "sk"),
    ("whois.sr", "sr"),
    ("whois.sx", "sx"),
    ("whois.ta.sgnic.sg", "xn--clchc0ea0b2g2a9gcd"),
    ("whois.tcinet.ru", "ru su xn--p1ai"),
    (
        "whois.teleinfo.cn",
        "anquan shouji xihuan xn--3ds443g xn--fiq228c5hs xn--vuq861b yun",
    ),
    ("whois.thnic.co.th", "th xn--o3cw4h"),
    ("whois.tld.ee", "ee"),
    ("whois.tld.mu", "mu"),
    ("whois.tld.sy", "sy xn--ogbpf8fl"),
    ("whois.tonicregistry.to", "to"),
    ("whois.trabis.gov.tr", "tr"),
    ("whois.twnic.net.tw", "tw xn--kprw13d xn--kpry57d"),
    ("whois.tznic.or.tz", "tz"),
    ("whois.ua", "ua"),
    ("whois.uniregistry.net", "juegos link"),
    ("whois.verisign-grs.com", "com net"),
    ("whois.weare.ie", "ie"),
    ("whois.website.ws", "ws"),
    ("whois.y.net.ye", "ye"),
    ("whois.zh.sgnic.sg", "xn--yfro4i67o"),
    ("whois.zicta.zm", "zm"),
    ("whois1.nic.bi", "bi"),
    ("www.whois.fj", "fj"),
];

/// Unicode U-labels of the IDN TLDs above. Each is keyed under the same
/// server as its punycode A-label, so the catalog lists both forms.
const IDN_ALIASES: &str = "
    vermögensberater vermögensberatung ευ бг бел дети ею католик ком мкд мон москва онлайн орг рф
    сайт срб укр қаз հայ ישראל קום ابوظبي الجزائر السعودية العليان امارات ایران بارت بازار بيتك
    بھارت تونس سورية شبكة عراق عرب عمان فلسطين قطر كاثوليك كوم مصر مليسيا موريتانيا موقع همراه ڀارت
    कॉम नेट भारत भारतम् भारोत संगठन ভারত ভাৰত ਭਾਰਤ ભારત ଭାରତ இந்தியா சிங்கப்பூர் భారత్ ಭಾರತ ഭാരതം คอม ไทย
    ລາວ アマゾン クラウド コム ストア セール ファッション ポイント 中信 中国 中國 中文网 亚马逊 企业
    佛山 信息 八卦 公司 公益 台湾 台灣 商城 商店 嘉里 嘉里大酒店 在线 大拿 天主教 娱乐 家電 广东
    微博 慈善 我爱你 手机 政务 政府 新加坡 新闻 时尚 書籍 机构 淡马锡 游戏 澳門 点看 移动 组织机构
    网址 网店 网站 网络 联通 购物 通販 集团 電訊盈科 飞利浦 食品 香格里拉 香港 닷넷 닷컴 삼성 한국
";

/// WHOIS servers for *second-level* registry zones. Some ccTLDs have no
/// port-43 WHOIS at the TLD itself (IANA publishes an empty `whois:` field)
/// while registrations live under SLD zones with a working registry server.
/// Kept separate from [`WHOIS_SERVERS`] so the TLD catalog ([`all_tlds`])
/// and TLD-keyed lookups stay pure-TLD.
static SLD_WHOIS_SERVERS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // ZACR (ZA Central Registry) — .za has no top-level WHOIS.
    m.insert("co.za", "whois.registry.net.za");
    m.insert("net.za", "whois.registry.net.za");
    m.insert("org.za", "whois.registry.net.za");
    m.insert("web.za", "whois.registry.net.za");
    m
});

/// Looks up the WHOIS server for a TLD, accepting either form of an IDN TLD:
/// the Unicode U-label (e.g. `рф`, `中国`) or the punycode A-label
/// (`xn--p1ai`, `xn--fiqs8s`). The map keys both forms for every IDN entry,
/// and a non-ASCII input that misses (or drifts out of the alias section) is
/// additionally retried under its A-label, so the two forms can never resolve
/// differently.
pub fn get_whois_server(tld: &str) -> Option<&'static str> {
    let lower = tld.to_lowercase();
    if let Some(server) = WHOIS_SERVERS.get(lower.as_str()) {
        return Some(server);
    }
    if !lower.is_ascii() {
        if let Ok(ascii) = crate::validation::domain_to_ascii(&lower) {
            return WHOIS_SERVERS.get(ascii.as_str()).map(String::as_str);
        }
    }
    None
}

/// Resolves the WHOIS server for a full domain name, preferring the most
/// specific match: a second-level registry zone (e.g. `co.za`) before the
/// plain TLD. Use this over [`get_whois_server`] whenever the full domain is
/// available. An IDN domain is converted to its A-labels first, so callers
/// may pass either `пример.рф` or `xn--e1afmkfd.xn--p1ai`.
pub fn get_whois_server_for_domain(domain: &str) -> Option<&'static str> {
    let lower = domain.trim_end_matches('.').to_lowercase();
    let lower = if lower.is_ascii() {
        lower
    } else {
        crate::validation::domain_to_ascii(&lower).unwrap_or(lower)
    };
    let labels: Vec<&str> = lower.rsplit('.').collect();
    if labels.len() >= 2 {
        let sld_zone = format!("{}.{}", labels[1], labels[0]);
        if let Some(server) = SLD_WHOIS_SERVERS.get(sld_zone.as_str()) {
            return Some(server);
        }
    }
    labels.first().and_then(|tld| get_whois_server(tld))
}

pub fn get_tld(domain: &str) -> Option<&str> {
    domain.rsplit('.').next()
}

/// Returns a suggested registry website URL for a TLD.
/// Derives the URL from the WHOIS server hostname when possible. A Unicode
/// IDN TLD is converted to its A-label so derived URLs and the IANA fallback
/// page use the canonical punycode form (IANA's root-db URLs are A-label
/// keyed: `.../db/xn--p1ai.html`, not `.../db/рф.html`).
pub fn get_registry_url(tld: &str) -> Option<String> {
    let tld_lower = tld.to_lowercase();
    let tld_lower = if tld_lower.is_ascii() {
        tld_lower
    } else {
        crate::validation::domain_to_ascii(&tld_lower).unwrap_or(tld_lower)
    };

    // Special cases for well-known registries
    match tld_lower.as_str() {
        "com" | "net" | "cc" | "tv" => {
            return Some("https://www.verisign.com/en_US/domain-names/index.xhtml".to_string())
        }
        "org" => return Some("https://thenew.org/org-people/domain-management/whois/".to_string()),
        "edu" => return Some("https://www.educause.edu/whois".to_string()),
        "gov" => return Some("https://domains.dotgov.gov/".to_string()),
        "app" | "dev" | "page" => {
            return Some("https://www.registry.google/policies/whois/".to_string())
        }
        _ => {}
    }

    // Try to derive URL from WHOIS server
    if let Some(whois_server) = get_whois_server(&tld_lower) {
        // Pattern: whois.nic.XX -> https://nic.XX, but ONLY when the trailing
        // label actually equals the queried TLD. Many brand TLDs share a single
        // registry host (e.g. datsun/nissan/jcb -> whois.nic.gmo), so blindly
        // stripping the prefix would point users at an unrelated registry
        // (https://nic.gmo). When it doesn't match, fall through to the IANA
        // page, which is always correct for the requested TLD.
        if let Some(suffix) = whois_server.strip_prefix("whois.nic.") {
            if suffix == tld_lower {
                return Some(format!("https://nic.{}", suffix));
            }
        }
        // Pattern: whois.XX -> https://www.nic.XX or https://XX registry
        if whois_server.starts_with("whois.") {
            // For ccTLDs, try the nic.TLD pattern
            if tld_lower.len() == 2 {
                return Some(format!("https://nic.{}", tld_lower));
            }
        }
    }

    // Fallback: suggest IANA's TLD info page
    Some(format!(
        "https://www.iana.org/domains/root/db/{}.html",
        tld_lower
    ))
}

/// TLDs that are intentionally absent from `WHOIS_SERVERS` (RDAP-only — see the
/// note on that map) but are still valid, lookupable TLDs. Listed here so the
/// TLD browser can surface them even though they have no WHOIS server. These
/// all resolve via RDAP (`lookup_tld` fills `rdap_url` from IANA bootstrap).
/// The Google IDN TLDs appear in both punycode and Unicode forms, matching how
/// `WHOIS_SERVERS` keys its IDN entries.
pub const RDAP_ONLY_TLDS: &str = "
    ads android app boo cal channel chrome dad day dclk dev docs drive eat esq fly foo gbiz gle
    gmail goog google guge hangout here how ing map meet meme mov new nexus page phd play prod prof
    rsvp search soy youtube zip xn--flw351e xn--q9jyb4c xn--qcka1pmc みんな グーグル 谷歌
";

/// TLDs whose port-43 WHOIS servers are dead and were removed from
/// `WHOIS_SERVERS` (2026-07-04 cleanup waves — see the module-level
/// "Intentional omissions" doc). They are still valid, delegated TLDs, so the
/// catalog must keep listing them: the gTLDs resolve via RDAP, and the ccTLDs
/// fall back to `lookup_tld`'s registry-URL guidance. IDN TLDs appear in both
/// Unicode and punycode forms, matching how `WHOIS_SERVERS` keyed them.
pub const WHOIS_RETIRED_TLDS: &str = "
    apple brussels cymru wales vlaanderen pharmacy na xn--p1acf рус lk xn--fzc2c9e2c ලංකා
    xn--xkc2al3hye2a இலங்கை mt
";

/// Delegated TLDs for which IANA publishes no `whois:` server at all — mostly
/// dot-brand gTLDs (`.netflix`, `.hsbc`) plus a number of ccTLDs (`.al`,
/// `.aq`, `.eg`) and IDN ccTLDs. Sourced from the same upstream sync as
/// [`WHOIS_SERVERS`] (entries with a null server, cross-checked against IANA
/// 2026-08-07). Catalog-only: there is nothing to put in the WHOIS map, but
/// they are valid, lookupable TLDs the TLD browser must list — `lookup_tld`
/// fills `rdap_url` from IANA bootstrap where the registry runs RDAP and
/// always supplies registry-URL guidance. `.za` is special: no top-level
/// WHOIS, but its SLD registry zones (`co.za`, …) resolve via
/// [`SLD_WHOIS_SERVERS`]. IDN TLDs appear in both Unicode and punycode forms,
/// matching how `WHOIS_SERVERS` keys its IDN entries.
pub const NO_WHOIS_TLDS: &str = "
    able aetna aig al americanexpress amex amica analytics ao aq aramco athleta axa az ba banamex bb
    bd booking bs bt bv calvinklein caravan cbn cbre cg chase cisco citi citic ck cu cw cy dell dhl
    dj dupont eg er et farmers ferrero fk flickr flir ford frontier ftr gap gb gm gr grainger gt gu
    gw hbo health homegoods homesense hsbc hyatt ieee intuit ipiranga itau jm jmp jnj jo jpmorgan kh
    km kp kpmg kpn kred lanxess lilly lincoln lr marshalls mattel mh mil mint mlb mp mv nba ne
    netflix neustar nfl ni nike np nr pa pfizer ph pn praxi pru prudential py sas sj sohu staples
    statefarm sv sz target tj tjmaxx tjx tkmaxx tt va vivo vn weather weatherchannel web williamhill
    winners xn--54b7fta0cc xn--czr694b xn--imr513n xn--mgba3a3ejt xn--mgbai9azgqp6j xn--mgbayh7gpa
    xn--mgbc0a9azcg xn--mgbcpq6gpa1a xn--mgbpl2fh xn--node xn--nyqy26a xn--otu796d xn--qxam
    xn--rhqv96g za zw ελ ارامكو الاردن البحرين المغرب سودان پاکستان বাংলা გე 世界 健康 商标 招聘
    餐厅
";

/// Returns every TLD seer knows about: the WHOIS server map keys unioned with
/// the RDAP-only, WHOIS-retired, and no-WHOIS TLDs, sorted and deduplicated.
/// Backs the TUI TLD browser so it can list the full ~1,570-entry catalog
/// instead of a hardcoded handful.
pub fn all_tlds() -> &'static [&'static str] {
    static ALL: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        let mut v: Vec<&'static str> = WHOIS_SERVERS.keys().copied().collect();
        for list in [RDAP_ONLY_TLDS, WHOIS_RETIRED_TLDS, NO_WHOIS_TLDS] {
            v.extend(list.split_ascii_whitespace());
        }
        v.sort_unstable();
        v.dedup();
        v
    });
    &ALL
}

#[cfg(test)]
mod all_tlds_tests {
    use super::*;

    /// TLDs whose dead WHOIS servers were removed from the map (2026-07-04
    /// cleanup waves) are still valid TLDs and must remain discoverable in
    /// the catalog — losing them from `all_tlds()` breaks the TUI's `:tld`
    /// command and browser for legitimate TLDs.
    #[test]
    fn whois_retired_tlds_stay_in_catalog() {
        let tlds = all_tlds();
        for tld in [
            "apple",
            "brussels",
            "cymru",
            "wales",
            "vlaanderen",
            "pharmacy",
            "na",
            "xn--p1acf",
            "рус",
            "lk",
            "xn--fzc2c9e2c",
            "ලංකා",
            "xn--xkc2al3hye2a",
            "இலங்கை",
            "mt",
        ] {
            assert!(
                tlds.binary_search(&tld).is_ok(),
                ".{tld} missing from all_tlds() — WHOIS-retired TLDs must stay in the catalog"
            );
        }
    }

    #[test]
    fn all_tlds_is_sorted_deduped_and_large() {
        let tlds = all_tlds();
        assert!(
            tlds.len() > 1500,
            "expected the full catalog (incl. no-WHOIS TLDs), got {}",
            tlds.len()
        );
        // Sorted + deduplicated.
        for w in tlds.windows(2) {
            assert!(w[0] < w[1], "not strictly sorted at {:?}", w);
        }
    }

    /// Delegated TLDs with no IANA-published WHOIS server (dot-brands, some
    /// ccTLDs) are catalog-only: they must appear in `all_tlds()` so the TLD
    /// browser lists them, must NOT have a `WHOIS_SERVERS` entry (there is no
    /// server), and must not double-list in the other catalog consts.
    #[test]
    fn no_whois_tlds_are_catalog_only_and_disjoint() {
        let tlds = all_tlds();
        let others: Vec<&str> = RDAP_ONLY_TLDS
            .split_ascii_whitespace()
            .chain(WHOIS_RETIRED_TLDS.split_ascii_whitespace())
            .collect();
        for tld in NO_WHOIS_TLDS.split_ascii_whitespace() {
            assert!(
                tlds.binary_search(&tld).is_ok(),
                ".{tld} missing from all_tlds() — no-WHOIS TLDs must stay in the catalog"
            );
            assert!(
                get_whois_server(tld).is_none(),
                ".{tld} is listed as no-WHOIS but resolves to a WHOIS server"
            );
            assert!(
                !others.contains(&tld),
                ".{tld} must appear in exactly one catalog list"
            );
        }
    }

    /// IDN entries in `NO_WHOIS_TLDS` appear in both Unicode and punycode
    /// forms, exactly paired — same convention (and same drift-guard) as the
    /// WHOIS server map's alias entries.
    #[test]
    fn no_whois_idn_tlds_are_paired_in_both_forms() {
        let entries: Vec<&str> = NO_WHOIS_TLDS.split_ascii_whitespace().collect();
        let set: std::collections::HashSet<&str> = entries.iter().copied().collect();
        let unicode_entries: Vec<&&str> = entries.iter().filter(|t| !t.is_ascii()).collect();
        assert!(!unicode_entries.is_empty(), "expected IDN no-WHOIS TLDs");
        for tld in &unicode_entries {
            let ascii = crate::validation::domain_to_ascii(tld)
                .unwrap_or_else(|_| panic!("no-WHOIS IDN TLD {tld} must convert to an A-label"));
            assert!(
                set.contains(ascii.as_str()),
                "Unicode no-WHOIS TLD {tld} lacks its punycode form {ascii}"
            );
        }
        let punycode_count = entries.iter().filter(|t| t.starts_with("xn--")).count();
        assert_eq!(
            unicode_entries.len(),
            punycode_count,
            "every punycode no-WHOIS entry must have exactly one Unicode form"
        );
    }

    #[test]
    fn all_tlds_includes_whois_and_rdap_only() {
        let tlds = all_tlds();
        // A WHOIS-mapped TLD and an RDAP-only one both appear.
        assert!(tlds.contains(&"com"), "com (WHOIS) should be present");
        assert!(tlds.contains(&"app"), "app (RDAP-only) should be present");
        assert!(tlds.contains(&"dev"), "dev (RDAP-only) should be present");
        // Google TLDs added in the 2026-08-07 upstream sync, including the
        // IDN ones in both forms.
        for tld in ["dclk", "map", "prod", "xn--q9jyb4c", "みんな", "谷歌"] {
            assert!(
                tlds.binary_search(&tld).is_ok(),
                ".{tld} (Google, RDAP-only) should be in the catalog"
            );
        }
    }

    /// The map keys every IDN TLD under both its punycode A-label and its
    /// Unicode U-label. Lock the two sections together: each Unicode key must
    /// convert to an A-label that is also in the map with the SAME server,
    /// and the section sizes must match (each A-label has exactly one
    /// U-label), so neither side can drift when syncing from upstream.
    #[test]
    fn unicode_aliases_agree_with_punycode_entries() {
        let unicode_keys: Vec<&str> = WHOIS_SERVERS
            .keys()
            .copied()
            .filter(|k| !k.is_ascii())
            .collect();
        assert!(!unicode_keys.is_empty(), "expected Unicode alias entries");
        for key in &unicode_keys {
            let ascii = crate::validation::domain_to_ascii(key)
                .unwrap_or_else(|_| panic!("Unicode key {key} must convert to an A-label"));
            assert_eq!(
                WHOIS_SERVERS.get(ascii.as_str()),
                WHOIS_SERVERS.get(key),
                "alias {key} and its A-label {ascii} must map to the same server"
            );
        }
        let punycode_count = WHOIS_SERVERS
            .keys()
            .filter(|k| k.starts_with("xn--"))
            .count();
        assert_eq!(
            unicode_keys.len(),
            punycode_count,
            "every punycode entry must have exactly one Unicode alias"
        );
    }

    /// Each TLD appears in exactly one table row, and every U-label alias
    /// resolved through its A-label — a duplicate would silently override an
    /// earlier row, a dropped alias would vanish from the catalog.
    #[test]
    fn server_tables_list_each_tld_once() {
        let listed = NIC_TLDS.split_ascii_whitespace().count()
            + HOSTED_TLDS
                .iter()
                .map(|(_, tlds)| tlds.split_ascii_whitespace().count())
                .sum::<usize>()
            + IDN_ALIASES.split_ascii_whitespace().count();
        assert_eq!(listed, WHOIS_SERVERS.len());
    }

    /// `get_whois_server` accepts either form of an IDN TLD (and any casing);
    /// both must resolve to the same server.
    #[test]
    fn get_whois_server_accepts_unicode_and_punycode_forms() {
        assert_eq!(get_whois_server("рф"), Some("whois.tcinet.ru"));
        assert_eq!(get_whois_server("xn--p1ai"), Some("whois.tcinet.ru"));
        assert_eq!(get_whois_server("РФ"), Some("whois.tcinet.ru"));
        assert_eq!(get_whois_server("XN--P1AI"), Some("whois.tcinet.ru"));
        assert_eq!(get_whois_server("中国"), Some("whois.cnnic.cn"));
        assert_eq!(get_whois_server("ไทย"), Some("whois.thnic.co.th"));
    }

    /// 2026-08-07 upstream sync: CONAC's gTLDs moved off the shared
    /// whois.conac.cn host to per-TLD servers (IANA records changed
    /// 2026-07-21). Both forms must follow.
    #[test]
    fn conac_tlds_moved_to_per_tld_servers() {
        assert_eq!(
            get_whois_server("xn--55qw42g"),
            Some("whois.nic.xn--55qw42g")
        );
        assert_eq!(get_whois_server("公益"), Some("whois.nic.xn--55qw42g"));
        assert_eq!(
            get_whois_server("xn--zfr164b"),
            Some("whois.nic.xn--zfr164b")
        );
        assert_eq!(get_whois_server("政务"), Some("whois.nic.xn--zfr164b"));
    }

    /// Full IDN domains resolve to their TLD's server whether given as
    /// U-labels or A-labels (callers may bypass normalize_domain).
    #[test]
    fn get_whois_server_for_domain_accepts_idn_domains() {
        assert_eq!(
            get_whois_server_for_domain("пример.рф"),
            Some("whois.tcinet.ru")
        );
        assert_eq!(
            get_whois_server_for_domain("xn--e1afmkfd.xn--p1ai"),
            Some("whois.tcinet.ru")
        );
        // FQDN form (trailing root dot) still converts.
        assert_eq!(
            get_whois_server_for_domain("пример.рф."),
            Some("whois.tcinet.ru")
        );
        assert_eq!(
            get_whois_server_for_domain("例え.jp"),
            Some("whois.jprs.jp")
        );
    }

    /// Registry URLs for IDN TLDs use the canonical A-label: IANA's root-db
    /// pages are punycode-keyed, and derived nic.<tld> hosts only exist in
    /// DNS under their A-label.
    #[test]
    fn get_registry_url_uses_punycode_for_idn_tlds() {
        assert_eq!(
            get_registry_url("рф").as_deref(),
            Some("https://www.iana.org/domains/root/db/xn--p1ai.html")
        );
        // whois.nic.xn--d1acj3b matches the converted TLD, so the derived
        // registry URL is kept — under the A-label, never the U-label.
        assert_eq!(
            get_registry_url("дети").as_deref(),
            Some("https://nic.xn--d1acj3b")
        );
        assert_eq!(
            get_registry_url("дети"),
            get_registry_url("xn--d1acj3b"),
            "both forms of an IDN TLD must produce the same registry URL"
        );
    }

    #[test]
    fn get_registry_url_does_not_misattribute_shared_whois_hosts() {
        // Many brand TLDs share one registry host (whois.nic.gmo). Deriving the
        // URL by stripping the prefix must NOT point .datsun at the .gmo
        // registry; it should fall through to the always-correct IANA page.
        assert_eq!(
            get_registry_url("datsun").as_deref(),
            Some("https://www.iana.org/domains/root/db/datsun.html")
        );
        // But when the trailing label really is the TLD, the derivation is kept.
        assert_eq!(get_registry_url("gmo").as_deref(), Some("https://nic.gmo"));
    }

    /// TLDs whose WHOIS hostnames are dead and whose IANA records no longer
    /// publish a `whois:` field (RDAP-only transitions, removed 2026-07-04)
    /// must stay out of the map — see the module-level "Intentional
    /// omissions" doc before re-adding any of them.
    #[test]
    fn iana_delisted_whois_servers_stay_removed() {
        for tld in [
            "apple",
            "brussels",
            "cymru",
            "wales",
            "vlaanderen",
            "pharmacy",
            "na",
            "xn--p1acf",
            "рус",
            // Second wave (ccTLD follow-up audit, same day): servers answer
            // nothing and IANA's whois: field is empty. (.ps is NOT here: its
            // registry moved to whois.registry.ps — see relocated test below.)
            // The Unicode forms of the .lk IDN TLDs must miss too — the
            // punycode fallback in get_whois_server must not resurrect them.
            "lk",
            "xn--fzc2c9e2c",
            "ලංකා",
            "xn--xkc2al3hye2a",
            "இலங்கை",
            "mt",
        ] {
            assert!(
                get_whois_server(tld).is_none(),
                ".{tld} must not be mapped (IANA-delisted, dead hostname)"
            );
        }
    }

    /// Registries found by live probing (2026-07-04 hostname-pattern hunt)
    /// whose working servers are NOT what IANA/upstream lists publish:
    /// ANINF runs port-43 for .ga at whois.nic.ga (IANA lists none, Freenom
    /// aftermath) and PNINA relocated .ps from the dead whois.pnina.ps to
    /// whois.registry.ps (IANA record stale). Aliases follow the base TLD.
    #[test]
    fn relocated_and_unlisted_cctld_servers_are_mapped() {
        assert_eq!(get_whois_server("ga"), Some("whois.nic.ga"));
        assert_eq!(get_whois_server("ps"), Some("whois.registry.ps"));
        assert_eq!(get_whois_server("xn--ygbi2ammx"), Some("whois.registry.ps"));
        assert_eq!(get_whois_server("فلسطين"), Some("whois.registry.ps"));
    }

    /// Registries that operate WHOIS for *second-level* zones only: the bare
    /// ccTLD has no port-43 WHOIS (IANA `whois:` is empty), but registrations
    /// live under SLD zones with a working registry server — e.g. ZACR serves
    /// co.za/net.za/org.za/web.za via whois.registry.net.za.
    #[test]
    fn sld_zones_resolve_before_tld() {
        assert_eq!(
            get_whois_server_for_domain("google.co.za"),
            Some("whois.registry.net.za")
        );
        assert_eq!(
            get_whois_server_for_domain("example.web.za"),
            Some("whois.registry.net.za")
        );
        // Bare .za still has no server (IANA publishes none).
        assert_eq!(get_whois_server_for_domain("nic.za"), None);
        // Regular TLD lookups are unaffected.
        assert_eq!(
            get_whois_server_for_domain("example.com"),
            Some("whois.verisign-grs.com")
        );
        // A two-label suffix that is NOT an SLD zone falls through to the TLD
        // (uk covers co.uk).
        assert_eq!(
            get_whois_server_for_domain("bbc.co.uk"),
            Some("whois.nic.uk")
        );
        // Single-label input (just a TLD) must not panic; it resolves via the
        // plain TLD path.
        assert_eq!(
            get_whois_server_for_domain("com"),
            Some("whois.verisign-grs.com")
        );
    }
}
