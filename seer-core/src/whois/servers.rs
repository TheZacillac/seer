use once_cell::sync::Lazy;
use std::collections::HashMap;

pub static WHOIS_SERVERS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Generic TLDs
    m.insert("com", "whois.verisign-grs.com");
    m.insert("net", "whois.verisign-grs.com");
    m.insert("org", "whois.pir.org");
    m.insert("info", "whois.afilias.net");
    m.insert("biz", "whois.biz");
    m.insert("name", "whois.nic.name");
    m.insert("mobi", "whois.afilias.net");
    m.insert("pro", "whois.registrypro.pro");
    m.insert("aero", "whois.aero");
    m.insert("asia", "whois.nic.asia");
    m.insert("cat", "whois.nic.cat");
    m.insert("coop", "whois.nic.coop");
    m.insert("edu", "whois.educause.edu");
    m.insert("gov", "whois.dotgov.gov");
    m.insert("int", "whois.iana.org");
    m.insert("jobs", "whois.nic.jobs");
    m.insert("mil", "whois.nic.mil");
    m.insert("museum", "whois.museum");
    m.insert("tel", "whois.nic.tel");
    m.insert("travel", "whois.nic.travel");
    m.insert("xxx", "whois.nic.xxx");

    // New gTLDs
    m.insert("app", "whois.nic.google");
    m.insert("dev", "whois.nic.google");
    m.insert("page", "whois.nic.google");
    m.insert("blog", "whois.nic.blog");
    m.insert("cloud", "whois.nic.cloud");
    m.insert("io", "whois.nic.io");
    m.insert("co", "whois.nic.co");
    m.insert("me", "whois.nic.me");
    m.insert("tv", "whois.nic.tv");
    m.insert("cc", "ccwhois.verisign-grs.com");
    m.insert("xyz", "whois.nic.xyz");
    m.insert("online", "whois.nic.online");
    m.insert("site", "whois.nic.site");
    m.insert("tech", "whois.nic.tech");
    m.insert("store", "whois.nic.store");
    m.insert("shop", "whois.nic.shop");

    // Additional popular gTLDs
    m.insert("ai", "whois.nic.ai");
    m.insert("gg", "whois.gg");
    m.insert("world", "whois.nic.world");
    m.insert("email", "whois.nic.email");
    m.insert("digital", "whois.nic.digital");
    m.insert("network", "whois.nic.network");
    m.insert("agency", "whois.nic.agency");
    m.insert("company", "whois.nic.company");
    m.insert("solutions", "whois.nic.solutions");
    m.insert("systems", "whois.nic.systems");
    m.insert("services", "whois.nic.services");
    m.insert("studio", "whois.nic.studio");
    m.insert("design", "whois.nic.design");
    m.insert("media", "whois.nic.media");
    m.insert("marketing", "whois.nic.marketing");
    m.insert("consulting", "whois.nic.consulting");
    m.insert("software", "whois.nic.software");
    m.insert("technology", "whois.nic.technology");
    m.insert("engineering", "whois.nic.engineering");
    m.insert("education", "whois.nic.education");
    m.insert("academy", "whois.nic.academy");
    m.insert("training", "whois.nic.training");
    m.insert("institute", "whois.nic.institute");
    m.insert("foundation", "whois.nic.foundation");
    m.insert("community", "whois.nic.community");
    m.insert("social", "whois.nic.social");
    m.insert("chat", "whois.nic.chat");
    m.insert("live", "whois.nic.live");
    m.insert("video", "whois.nic.video");
    m.insert("news", "whois.nic.news");
    m.insert("today", "whois.nic.today");
    m.insert("life", "whois.nic.life");
    m.insert("style", "whois.nic.style");
    m.insert("art", "whois.nic.art");
    m.insert("music", "whois.nic.music");
    m.insert("film", "whois.nic.film");
    m.insert("games", "whois.nic.games");
    m.insert("game", "whois.nic.game");
    m.insert("play", "whois.nic.play");
    m.insert("fun", "whois.nic.fun");
    m.insert("cool", "whois.nic.cool");
    m.insert("zone", "whois.nic.zone");
    m.insert("space", "whois.nic.space");
    m.insert("city", "whois.nic.city");
    m.insert("town", "whois.nic.town");
    m.insert("place", "whois.nic.place");
    m.insert("house", "whois.nic.house");
    m.insert("land", "whois.nic.land");
    m.insert("earth", "whois.nic.earth");
    m.insert("global", "whois.nic.global");
    m.insert("international", "whois.nic.international");
    m.insert("money", "whois.nic.money");
    m.insert("finance", "whois.nic.finance");
    m.insert("financial", "whois.nic.financial");
    m.insert("bank", "whois.nic.bank");
    m.insert("insurance", "whois.nic.insurance");
    m.insert("investments", "whois.nic.investments");
    m.insert("capital", "whois.nic.capital");
    m.insert("fund", "whois.nic.fund");
    m.insert("exchange", "whois.nic.exchange");
    m.insert("market", "whois.nic.market");
    m.insert("trade", "whois.nic.trade");
    m.insert("business", "whois.nic.business");
    m.insert("ventures", "whois.nic.ventures");
    m.insert("enterprises", "whois.nic.enterprises");
    m.insert("industries", "whois.nic.industries");
    m.insert("holdings", "whois.nic.holdings");
    m.insert("group", "whois.nic.group");
    m.insert("team", "whois.nic.team");
    m.insert("partners", "whois.nic.partners");
    m.insert("work", "whois.nic.work");
    m.insert("works", "whois.nic.works");
    m.insert("careers", "whois.nic.careers");
    m.insert("jobs", "whois.nic.jobs");
    m.insert("health", "whois.nic.health");
    m.insert("healthcare", "whois.nic.healthcare");
    m.insert("hospital", "whois.nic.hospital");
    m.insert("doctor", "whois.nic.doctor");
    m.insert("dental", "whois.nic.dental");
    m.insert("fitness", "whois.nic.fitness");
    m.insert("yoga", "whois.nic.yoga");
    m.insert("food", "whois.nic.food");
    m.insert("restaurant", "whois.nic.restaurant");
    m.insert("bar", "whois.nic.bar");
    m.insert("cafe", "whois.nic.cafe");
    m.insert("coffee", "whois.nic.coffee");
    m.insert("kitchen", "whois.nic.kitchen");
    m.insert("recipes", "whois.nic.recipes");
    m.insert("wine", "whois.nic.wine");
    m.insert("beer", "whois.nic.beer");
    m.insert("pizza", "whois.nic.pizza");
    m.insert("photography", "whois.nic.photography");
    m.insert("photo", "whois.nic.photo");
    m.insert("photos", "whois.nic.photos");
    m.insert("gallery", "whois.nic.gallery");
    m.insert("graphics", "whois.nic.graphics");
    m.insert("pictures", "whois.nic.pictures");
    m.insert("wedding", "whois.nic.wedding");
    m.insert("events", "whois.nic.events");
    m.insert("party", "whois.nic.party");
    m.insert("holiday", "whois.nic.holiday");
    m.insert("travel", "whois.nic.travel");
    m.insert("flights", "whois.nic.flights");
    m.insert("hotel", "whois.nic.hotel");
    m.insert("rentals", "whois.nic.rentals");
    m.insert("apartments", "whois.nic.apartments");
    m.insert("property", "whois.nic.property");
    m.insert("properties", "whois.nic.properties");
    m.insert("estate", "whois.nic.estate");
    m.insert("realty", "whois.nic.realty");
    m.insert("mortgage", "whois.nic.mortgage");
    m.insert("construction", "whois.nic.construction");
    m.insert("builders", "whois.nic.builders");
    m.insert("contractor", "whois.nic.contractor");
    m.insert("plumbing", "whois.nic.plumbing");
    m.insert("electrician", "whois.nic.electrician");
    m.insert("repair", "whois.nic.repair");
    m.insert("tools", "whois.nic.tools");
    m.insert("parts", "whois.nic.parts");
    m.insert("supply", "whois.nic.supply");
    m.insert("supplies", "whois.nic.supplies");
    m.insert("equipment", "whois.nic.equipment");
    m.insert("auto", "whois.nic.auto");
    m.insert("car", "whois.nic.car");
    m.insert("cars", "whois.nic.cars");
    m.insert("bike", "whois.nic.bike");
    m.insert("boats", "whois.nic.boats");
    m.insert("taxi", "whois.nic.taxi");
    m.insert("security", "whois.nic.security");
    m.insert("protection", "whois.nic.protection");
    m.insert("legal", "whois.nic.legal");
    m.insert("lawyer", "whois.nic.lawyer");
    m.insert("law", "whois.nic.law");
    m.insert("attorney", "whois.nic.attorney");
    m.insert("accountant", "whois.nic.accountant");
    m.insert("tax", "whois.nic.tax");
    m.insert("domains", "whois.nic.domains");
    m.insert("hosting", "whois.nic.hosting");
    m.insert("website", "whois.nic.website");
    m.insert("web", "whois.nic.web");
    m.insert("link", "whois.nic.link");
    m.insert("click", "whois.nic.click");
    m.insert("download", "whois.nic.download");
    m.insert("stream", "whois.nic.stream");
    m.insert("data", "whois.nic.data");
    m.insert("codes", "whois.nic.codes");
    m.insert("directory", "whois.nic.directory");
    m.insert("guide", "whois.nic.guide");
    m.insert("help", "whois.nic.help");
    m.insert("support", "whois.nic.support");
    m.insert("tips", "whois.nic.tips");
    m.insert("wiki", "whois.nic.wiki");
    m.insert("reviews", "whois.nic.reviews");
    m.insert("report", "whois.nic.report");
    m.insert("plus", "whois.nic.plus");
    m.insert("one", "whois.nic.one");
    m.insert("top", "whois.nic.top");
    m.insert("best", "whois.nic.best");
    m.insert("vip", "whois.nic.vip");
    m.insert("lol", "whois.nic.lol");
    m.insert("wtf", "whois.nic.wtf");
    m.insert("fail", "whois.nic.fail");
    m.insert("sucks", "whois.nic.sucks");
    m.insert("rocks", "whois.nic.rocks");
    m.insert("ninja", "whois.nic.ninja");
    m.insert("guru", "whois.nic.guru");
    m.insert("expert", "whois.nic.expert");
    m.insert("pro", "whois.nic.pro");
    m.insert("club", "whois.nic.club");
    m.insert("pub", "whois.nic.pub");
    m.insert("run", "whois.nic.run");
    m.insert("limited", "whois.nic.limited");
    m.insert("ltd", "whois.nic.ltd");
    m.insert("inc", "whois.nic.inc");
    m.insert("llc", "whois.nic.llc");
    m.insert("gmbh", "whois.nic.gmbh");
    m.insert("sarl", "whois.nic.sarl");
    m.insert("srl", "whois.nic.srl");

    // Country code TLDs
    m.insert("ac", "whois.nic.ac");
    m.insert("ad", "whois.nic.ad");
    m.insert("ae", "whois.aeda.net.ae");
    m.insert("af", "whois.nic.af");
    m.insert("ag", "whois.nic.ag");
    m.insert("ai", "whois.nic.ai");
    m.insert("al", "whois.ripe.net");
    m.insert("am", "whois.amnic.net");
    m.insert("ao", "whois.nic.ao");
    m.insert("ar", "whois.nic.ar");
    m.insert("as", "whois.nic.as");
    m.insert("at", "whois.nic.at");
    m.insert("au", "whois.auda.org.au");
    m.insert("aw", "whois.nic.aw");
    m.insert("ax", "whois.ax");
    m.insert("az", "whois.nic.az");
    m.insert("ba", "whois.nic.ba");
    m.insert("bb", "whois.nic.bb");
    m.insert("be", "whois.dns.be");
    m.insert("bf", "whois.nic.bf");
    m.insert("bg", "whois.register.bg");
    m.insert("bh", "whois.nic.bh");
    m.insert("bi", "whois.nic.bi");
    m.insert("bj", "whois.nic.bj");
    m.insert("bn", "whois.nic.bn");
    m.insert("bo", "whois.nic.bo");
    m.insert("br", "whois.registro.br");
    m.insert("bt", "whois.nic.bt");
    m.insert("bw", "whois.nic.net.bw");
    m.insert("by", "whois.cctld.by");
    m.insert("bz", "whois.afilias-grs.info");
    m.insert("ca", "whois.cira.ca");
    m.insert("cd", "whois.nic.cd");
    m.insert("cf", "whois.nic.cf");
    m.insert("ch", "whois.nic.ch");
    m.insert("ci", "whois.nic.ci");
    m.insert("ck", "whois.nic.ck");
    m.insert("cl", "whois.nic.cl");
    m.insert("cm", "whois.netcom.cm");
    m.insert("cn", "whois.cnnic.cn");
    m.insert("cr", "whois.nic.cr");
    m.insert("cu", "whois.nic.cu");
    m.insert("cv", "whois.nic.cv");
    m.insert("cw", "whois.nic.cw");
    m.insert("cx", "whois.nic.cx");
    m.insert("cy", "whois.nic.cy");
    m.insert("cz", "whois.nic.cz");
    m.insert("de", "whois.denic.de");
    m.insert("dj", "whois.nic.dj");
    m.insert("dk", "whois.dk-hostmaster.dk");
    m.insert("dm", "whois.nic.dm");
    m.insert("do", "whois.nic.do");
    m.insert("dz", "whois.nic.dz");
    m.insert("ec", "whois.nic.ec");
    m.insert("ee", "whois.tld.ee");
    m.insert("eg", "whois.nic.eg");
    m.insert("es", "whois.nic.es");
    m.insert("et", "whois.nic.et");
    m.insert("eu", "whois.eu");
    m.insert("fi", "whois.fi");
    m.insert("fj", "whois.nic.fj");
    m.insert("fm", "whois.nic.fm");
    m.insert("fo", "whois.nic.fo");
    m.insert("fr", "whois.nic.fr");
    m.insert("ga", "whois.nic.ga");
    m.insert("gd", "whois.nic.gd");
    m.insert("ge", "whois.nic.ge");
    m.insert("gf", "whois.nic.gf");
    m.insert("gg", "whois.gg");
    m.insert("gh", "whois.nic.gh");
    m.insert("gi", "whois.nic.gi");
    m.insert("gl", "whois.nic.gl");
    m.insert("gm", "whois.nic.gm");
    m.insert("gn", "whois.nic.gn");
    m.insert("gp", "whois.nic.gp");
    m.insert("gq", "whois.nic.gq");
    m.insert("gr", "whois.nic.gr");
    m.insert("gs", "whois.nic.gs");
    m.insert("gt", "whois.nic.gt");
    m.insert("gu", "whois.nic.gu");
    m.insert("gw", "whois.nic.gw");
    m.insert("gy", "whois.registry.gy");
    m.insert("hk", "whois.hkirc.hk");
    m.insert("hm", "whois.registry.hm");
    m.insert("hn", "whois.nic.hn");
    m.insert("hr", "whois.dns.hr");
    m.insert("ht", "whois.nic.ht");
    m.insert("hu", "whois.nic.hu");
    m.insert("id", "whois.id");
    m.insert("ie", "whois.iedr.ie");
    m.insert("il", "whois.isoc.org.il");
    m.insert("im", "whois.nic.im");
    m.insert("in", "whois.registry.in");
    m.insert("iq", "whois.nic.iq");
    m.insert("ir", "whois.nic.ir");
    m.insert("is", "whois.isnic.is");
    m.insert("it", "whois.nic.it");
    m.insert("je", "whois.je");
    m.insert("jm", "whois.nic.jm");
    m.insert("jo", "whois.nic.jo");
    m.insert("jp", "whois.jprs.jp");
    m.insert("ke", "whois.kenic.or.ke");
    m.insert("kg", "whois.kg");
    m.insert("kh", "whois.nic.kh");
    m.insert("ki", "whois.nic.ki");
    m.insert("km", "whois.nic.km");
    m.insert("kn", "whois.nic.kn");
    m.insert("kr", "whois.kr");
    m.insert("kw", "whois.nic.kw");
    m.insert("ky", "whois.kyregistry.ky");
    m.insert("kz", "whois.nic.kz");
    m.insert("la", "whois.nic.la");
    m.insert("lb", "whois.nic.lb");
    m.insert("lc", "whois.nic.lc");
    m.insert("li", "whois.nic.li");
    m.insert("lk", "whois.nic.lk");
    m.insert("lr", "whois.nic.lr");
    m.insert("ls", "whois.nic.ls");
    m.insert("lt", "whois.domreg.lt");
    m.insert("lu", "whois.dns.lu");
    m.insert("lv", "whois.nic.lv");
    m.insert("ly", "whois.nic.ly");
    m.insert("ma", "whois.registre.ma");
    m.insert("mc", "whois.nic.mc");
    m.insert("md", "whois.nic.md");
    m.insert("mg", "whois.nic.mg");
    m.insert("mk", "whois.marnet.mk");
    m.insert("ml", "whois.nic.ml");
    m.insert("mm", "whois.nic.mm");
    m.insert("mn", "whois.nic.mn");
    m.insert("mo", "whois.monic.mo");
    m.insert("mp", "whois.nic.mp");
    m.insert("mq", "whois.nic.mq");
    m.insert("mr", "whois.nic.mr");
    m.insert("ms", "whois.nic.ms");
    m.insert("mt", "whois.nic.mt");
    m.insert("mu", "whois.nic.mu");
    m.insert("mv", "whois.nic.mv");
    m.insert("mw", "whois.nic.mw");
    m.insert("mx", "whois.mx");
    m.insert("my", "whois.mynic.my");
    m.insert("mz", "whois.nic.mz");
    m.insert("na", "whois.na-nic.com.na");
    m.insert("nc", "whois.nc");
    m.insert("nf", "whois.nic.nf");
    m.insert("ng", "whois.nic.net.ng");
    m.insert("ni", "whois.nic.ni");
    m.insert("nl", "whois.domain-registry.nl");
    m.insert("no", "whois.norid.no");
    m.insert("np", "whois.nic.np");
    m.insert("nr", "whois.nic.nr");
    m.insert("nu", "whois.iis.nu");
    m.insert("nz", "whois.srs.net.nz");
    m.insert("om", "whois.nic.om");
    m.insert("pa", "whois.nic.pa");
    m.insert("pe", "whois.nic.pe");
    m.insert("pf", "whois.registry.pf");
    m.insert("pg", "whois.nic.pg");
    m.insert("ph", "whois.nic.ph");
    m.insert("pk", "whois.pknic.net.pk");
    m.insert("pl", "whois.dns.pl");
    m.insert("pm", "whois.nic.pm");
    m.insert("pn", "whois.nic.pn");
    m.insert("pr", "whois.nic.pr");
    m.insert("ps", "whois.nic.ps");
    m.insert("pt", "whois.dns.pt");
    m.insert("pw", "whois.nic.pw");
    m.insert("py", "whois.nic.py");
    m.insert("qa", "whois.registry.qa");
    m.insert("re", "whois.nic.re");
    m.insert("ro", "whois.rotld.ro");
    m.insert("rs", "whois.rnids.rs");
    m.insert("ru", "whois.tcinet.ru");
    m.insert("rw", "whois.nic.rw");
    m.insert("sa", "whois.nic.net.sa");
    m.insert("sb", "whois.nic.sb");
    m.insert("sc", "whois.nic.sc");
    m.insert("sd", "whois.nic.sd");
    m.insert("se", "whois.iis.se");
    m.insert("sg", "whois.sgnic.sg");
    m.insert("sh", "whois.nic.sh");
    m.insert("si", "whois.register.si");
    m.insert("sk", "whois.sk-nic.sk");
    m.insert("sl", "whois.nic.sl");
    m.insert("sm", "whois.nic.sm");
    m.insert("sn", "whois.nic.sn");
    m.insert("so", "whois.nic.so");
    m.insert("sr", "whois.nic.sr");
    m.insert("ss", "whois.nic.ss");
    m.insert("st", "whois.nic.st");
    m.insert("su", "whois.tcinet.ru");
    m.insert("sv", "whois.svnet.sv");
    m.insert("sx", "whois.sx");
    m.insert("sy", "whois.nic.sy");
    m.insert("sz", "whois.nic.sz");
    m.insert("tc", "whois.nic.tc");
    m.insert("td", "whois.nic.td");
    m.insert("tf", "whois.nic.tf");
    m.insert("tg", "whois.nic.tg");
    m.insert("th", "whois.thnic.co.th");
    m.insert("tj", "whois.nic.tj");
    m.insert("tk", "whois.nic.tk");
    m.insert("tl", "whois.nic.tl");
    m.insert("tm", "whois.nic.tm");
    m.insert("tn", "whois.ati.tn");
    m.insert("to", "whois.tonic.to");
    m.insert("tr", "whois.trabis.gov.tr");
    m.insert("tt", "whois.nic.tt");
    m.insert("tv", "tvwhois.verisign-grs.com");
    m.insert("tw", "whois.twnic.net.tw");
    m.insert("tz", "whois.nic.tz");
    m.insert("ua", "whois.ua");
    m.insert("ug", "whois.nic.ug");
    m.insert("uk", "whois.nic.uk");
    m.insert("us", "whois.nic.us");
    m.insert("uy", "whois.nic.org.uy");
    m.insert("uz", "whois.cctld.uz");
    m.insert("vc", "whois.nic.vc");
    m.insert("ve", "whois.nic.ve");
    m.insert("vg", "whois.nic.vg");
    m.insert("vi", "whois.nic.vi");
    m.insert("vn", "whois.nic.vn");
    m.insert("vu", "whois.nic.vu");
    m.insert("wf", "whois.nic.wf");
    m.insert("ws", "whois.website.ws");
    m.insert("ye", "whois.nic.ye");
    m.insert("yt", "whois.nic.yt");
    m.insert("za", "whois.registry.net.za");
    m.insert("zm", "whois.nic.zm");
    m.insert("zw", "whois.nic.zw");

    m
});

pub fn get_whois_server(tld: &str) -> Option<&'static str> {
    WHOIS_SERVERS.get(tld.to_lowercase().as_str()).copied()
}

pub fn get_tld(domain: &str) -> Option<&str> {
    domain.rsplit('.').next()
}

/// Get a suggested registry website URL for a TLD.
/// This derives the URL from the WHOIS server hostname when possible.
pub fn get_registry_url(tld: &str) -> Option<String> {
    let tld_lower = tld.to_lowercase();

    // Special cases for well-known registries
    match tld_lower.as_str() {
        "com" | "net" | "cc" | "tv" => return Some("https://www.verisign.com/en_US/domain-names/index.xhtml".to_string()),
        "org" => return Some("https://thenew.org/org-people/domain-management/whois/".to_string()),
        "edu" => return Some("https://www.educause.edu/whois".to_string()),
        "gov" => return Some("https://domains.dotgov.gov/".to_string()),
        "app" | "dev" | "page" => return Some("https://www.registry.google/policies/whois/".to_string()),
        _ => {}
    }

    // Try to derive URL from WHOIS server
    if let Some(whois_server) = get_whois_server(&tld_lower) {
        // Pattern: whois.nic.XX -> https://nic.XX
        if let Some(suffix) = whois_server.strip_prefix("whois.nic.") {
            return Some(format!("https://nic.{}", suffix));
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
    Some(format!("https://www.iana.org/domains/root/db/{}.html", tld_lower))
}
