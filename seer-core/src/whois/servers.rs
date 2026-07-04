use once_cell::sync::Lazy;
use std::collections::HashMap;

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
/// (+ its `рус` alias). Do not re-add them from stale upstream lists without
/// re-checking IANA (`whois -h whois.iana.org <tld>`).
pub static WHOIS_SERVERS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // ============================================================
    // Generic TLDs (gTLDs) and New gTLDs
    // ============================================================
    m.insert("aaa", "whois.nic.aaa");
    m.insert("aarp", "whois.nic.aarp");
    m.insert("abb", "whois.nic.abb");
    m.insert("abbott", "whois.nic.abbott");
    m.insert("abbvie", "whois.nic.abbvie");
    m.insert("abc", "whois.nic.abc");
    m.insert("abogado", "whois.nic.abogado");
    m.insert("abudhabi", "whois.nic.abudhabi");
    m.insert("academy", "whois.nic.academy");
    m.insert("accenture", "whois.nic.accenture");
    m.insert("accountant", "whois.nic.accountant");
    m.insert("accountants", "whois.nic.accountants");
    m.insert("aco", "whois.nic.aco");
    m.insert("actor", "whois.nic.actor");
    m.insert("adult", "whois.nic.adult");
    m.insert("aeg", "whois.nic.aeg");
    m.insert("aero", "whois.aero");
    m.insert("afl", "whois.nic.afl");
    m.insert("africa", "whois.nic.africa");
    m.insert("agakhan", "whois.nic.agakhan");
    m.insert("agency", "whois.nic.agency");
    m.insert("airbus", "whois.nic.airbus");
    m.insert("airforce", "whois.nic.airforce");
    m.insert("airtel", "whois.nic.airtel");
    m.insert("akdn", "whois.nic.akdn");
    m.insert("alibaba", "whois.nic.alibaba");
    m.insert("alipay", "whois.nic.alipay");
    m.insert("allfinanz", "whois.nic.allfinanz");
    m.insert("allstate", "whois.nic.allstate");
    m.insert("ally", "whois.nic.ally");
    m.insert("alsace", "whois.nic.alsace");
    m.insert("alstom", "whois.nic.alstom");
    m.insert("amazon", "whois.nic.amazon");
    m.insert("americanfamily", "whois.nic.americanfamily");
    m.insert("amfam", "whois.nic.amfam");
    m.insert("amsterdam", "whois.nic.amsterdam");
    m.insert("anquan", "whois.teleinfo.cn");
    m.insert("anz", "whois.nic.anz");
    m.insert("aol", "whois.nic.aol");
    m.insert("apartments", "whois.nic.apartments");
    m.insert("aquarelle", "whois.nic.aquarelle");
    m.insert("arab", "whois.nic.arab");
    m.insert("archi", "whois.nic.archi");
    m.insert("army", "whois.nic.army");
    m.insert("arpa", "whois.iana.org");
    m.insert("art", "whois.nic.art");
    m.insert("arte", "whois.nic.arte");
    m.insert("asda", "whois.nic.asda");
    m.insert("asia", "whois.nic.asia");
    m.insert("associates", "whois.nic.associates");
    m.insert("attorney", "whois.nic.attorney");
    m.insert("auction", "whois.nic.auction");
    m.insert("audi", "whois.nic.audi");
    m.insert("audible", "whois.nic.audible");
    m.insert("audio", "whois.nic.audio");
    m.insert("auspost", "whois.nic.auspost");
    m.insert("author", "whois.nic.author");
    m.insert("auto", "whois.nic.auto");
    m.insert("autos", "whois.nic.autos");
    m.insert("aws", "whois.nic.aws");
    m.insert("azure", "whois.nic.azure");
    m.insert("baby", "whois.nic.baby");
    m.insert("baidu", "whois.gtld.knet.cn");
    m.insert("band", "whois.nic.band");
    m.insert("bank", "whois.nic.bank");
    m.insert("bar", "whois.nic.bar");
    m.insert("barcelona", "whois.nic.barcelona");
    m.insert("barclaycard", "whois.nic.barclaycard");
    m.insert("barclays", "whois.nic.barclays");
    m.insert("barefoot", "whois.nic.barefoot");
    m.insert("bargains", "whois.nic.bargains");
    m.insert("baseball", "whois.nic.baseball");
    m.insert("basketball", "whois.nic.basketball");
    m.insert("bauhaus", "whois.nic.bauhaus");
    m.insert("bayern", "whois.nic.bayern");
    m.insert("bbc", "whois.nic.bbc");
    m.insert("bbt", "whois.nic.bbt");
    m.insert("bbva", "whois.nic.bbva");
    m.insert("bcg", "whois.nic.bcg");
    m.insert("bcn", "whois.nic.bcn");
    m.insert("beats", "whois.nic.beats");
    m.insert("beauty", "whois.nic.beauty");
    m.insert("beer", "whois.nic.beer");
    m.insert("berlin", "whois.nic.berlin");
    m.insert("best", "whois.nic.best");
    m.insert("bestbuy", "whois.nic.bestbuy");
    m.insert("bet", "whois.nic.bet");
    m.insert("bharti", "whois.nic.bharti");
    m.insert("bible", "whois.nic.bible");
    m.insert("bid", "whois.nic.bid");
    m.insert("bike", "whois.nic.bike");
    m.insert("bing", "whois.nic.bing");
    m.insert("bingo", "whois.nic.bingo");
    m.insert("bio", "whois.nic.bio");
    m.insert("biz", "whois.nic.biz");
    m.insert("black", "whois.nic.black");
    m.insert("blackfriday", "whois.nic.blackfriday");
    m.insert("blockbuster", "whois.nic.blockbuster");
    m.insert("blog", "whois.nic.blog");
    m.insert("bloomberg", "whois.nic.bloomberg");
    m.insert("blue", "whois.nic.blue");
    m.insert("bms", "whois.nic.bms");
    m.insert("bmw", "whois.nic.bmw");
    m.insert("bnpparibas", "whois.nic.bnpparibas");
    m.insert("boats", "whois.nic.boats");
    m.insert("boehringer", "whois.nic.boehringer");
    m.insert("bofa", "whois.nic.bofa");
    m.insert("bom", "whois.gtlds.nic.br");
    m.insert("bond", "whois.nic.bond");
    m.insert("book", "whois.nic.book");
    m.insert("bosch", "whois.nic.bosch");
    m.insert("bostik", "whois.nic.bostik");
    m.insert("boston", "whois.nic.boston");
    m.insert("bot", "whois.nic.bot");
    m.insert("boutique", "whois.nic.boutique");
    m.insert("box", "whois.nic.box");
    m.insert("bradesco", "whois.nic.bradesco");
    m.insert("bridgestone", "whois.nic.bridgestone");
    m.insert("broadway", "whois.nic.broadway");
    m.insert("broker", "whois.nic.broker");
    m.insert("brother", "whois.nic.brother");
    m.insert("build", "whois.nic.build");
    m.insert("builders", "whois.nic.builders");
    m.insert("business", "whois.nic.business");
    m.insert("buy", "whois.nic.buy");
    m.insert("buzz", "whois.nic.buzz");
    m.insert("bzh", "whois.nic.bzh");
    m.insert("cab", "whois.nic.cab");
    m.insert("cafe", "whois.nic.cafe");
    m.insert("call", "whois.nic.call");
    m.insert("cam", "whois.nic.cam");
    m.insert("camera", "whois.nic.camera");
    m.insert("camp", "whois.nic.camp");
    m.insert("canon", "whois.nic.canon");
    m.insert("capetown", "whois.nic.capetown");
    m.insert("capital", "whois.nic.capital");
    m.insert("capitalone", "whois.nic.capitalone");
    m.insert("car", "whois.nic.car");
    m.insert("cards", "whois.nic.cards");
    m.insert("care", "whois.nic.care");
    m.insert("career", "whois.nic.career");
    m.insert("careers", "whois.nic.careers");
    m.insert("cars", "whois.nic.cars");
    m.insert("casa", "whois.nic.casa");
    m.insert("case", "whois.nic.case");
    m.insert("cash", "whois.nic.cash");
    m.insert("casino", "whois.nic.casino");
    m.insert("cat", "whois.nic.cat");
    m.insert("catering", "whois.nic.catering");
    m.insert("catholic", "whois.nic.catholic");
    m.insert("cba", "whois.nic.cba");
    m.insert("center", "whois.nic.center");
    m.insert("ceo", "whois.nic.ceo");
    m.insert("cern", "whois.nic.cern");
    m.insert("cfa", "whois.nic.cfa");
    m.insert("cfd", "whois.nic.cfd");
    m.insert("chanel", "whois.nic.chanel");
    m.insert("charity", "whois.nic.charity");
    m.insert("chat", "whois.nic.chat");
    m.insert("cheap", "whois.nic.cheap");
    m.insert("chintai", "whois.nic.chintai");
    m.insert("christmas", "whois.nic.christmas");
    m.insert("church", "whois.nic.church");
    m.insert("cipriani", "whois.nic.cipriani");
    m.insert("circle", "whois.nic.circle");
    m.insert("citadel", "whois.nic.citadel");
    m.insert("city", "whois.nic.city");
    m.insert("claims", "whois.nic.claims");
    m.insert("cleaning", "whois.nic.cleaning");
    m.insert("click", "whois.registry.click");
    m.insert("clinic", "whois.nic.clinic");
    m.insert("clinique", "whois.nic.clinique");
    m.insert("clothing", "whois.nic.clothing");
    m.insert("cloud", "whois.nic.cloud");
    m.insert("club", "whois.nic.club");
    m.insert("clubmed", "whois.nic.clubmed");
    m.insert("coach", "whois.nic.coach");
    m.insert("codes", "whois.nic.codes");
    m.insert("coffee", "whois.nic.coffee");
    m.insert("college", "whois.nic.college");
    m.insert("cologne", "whois.ryce-rsp.com");
    m.insert("com", "whois.verisign-grs.com");
    m.insert("commbank", "whois.nic.commbank");
    m.insert("community", "whois.nic.community");
    m.insert("company", "whois.nic.company");
    m.insert("compare", "whois.nic.compare");
    m.insert("computer", "whois.nic.computer");
    m.insert("comsec", "whois.nic.comsec");
    m.insert("condos", "whois.nic.condos");
    m.insert("construction", "whois.nic.construction");
    m.insert("consulting", "whois.nic.consulting");
    m.insert("contact", "whois.nic.contact");
    m.insert("contractors", "whois.nic.contractors");
    m.insert("cooking", "whois.nic.cooking");
    m.insert("cool", "whois.nic.cool");
    m.insert("coop", "whois.nic.coop");
    m.insert("corsica", "whois.nic.corsica");
    m.insert("country", "whois.registry.click");
    m.insert("coupon", "whois.nic.coupon");
    m.insert("coupons", "whois.nic.coupons");
    m.insert("courses", "whois.nic.courses");
    m.insert("cpa", "whois.nic.cpa");
    m.insert("credit", "whois.nic.credit");
    m.insert("creditcard", "whois.nic.creditcard");
    m.insert("creditunion", "whois.nic.creditunion");
    m.insert("cricket", "whois.nic.cricket");
    m.insert("crown", "whois.nic.crown");
    m.insert("crs", "whois.nic.crs");
    m.insert("cruise", "whois.nic.cruise");
    m.insert("cruises", "whois.nic.cruises");
    m.insert("cuisinella", "whois.nic.cuisinella");
    m.insert("cyou", "whois.nic.cyou");
    m.insert("dance", "whois.nic.dance");
    m.insert("data", "whois.nic.data");
    m.insert("date", "whois.nic.date");
    m.insert("dating", "whois.nic.dating");
    m.insert("datsun", "whois.nic.gmo");
    m.insert("dds", "whois.nic.dds");
    m.insert("deal", "whois.nic.deal");
    m.insert("dealer", "whois.nic.dealer");
    m.insert("deals", "whois.nic.deals");
    m.insert("degree", "whois.nic.degree");
    m.insert("delivery", "whois.nic.delivery");
    m.insert("deloitte", "whois.nic.deloitte");
    m.insert("delta", "whois.nic.delta");
    m.insert("democrat", "whois.nic.democrat");
    m.insert("dental", "whois.nic.dental");
    m.insert("dentist", "whois.nic.dentist");
    m.insert("desi", "whois.nic.desi");
    m.insert("design", "whois.nic.design");
    m.insert("diamonds", "whois.nic.diamonds");
    m.insert("diet", "whois.nic.diet");
    m.insert("digital", "whois.nic.digital");
    m.insert("direct", "whois.nic.direct");
    m.insert("directory", "whois.nic.directory");
    m.insert("discount", "whois.nic.discount");
    m.insert("discover", "whois.nic.discover");
    m.insert("dish", "whois.nic.dish");
    m.insert("diy", "whois.registry.click");
    m.insert("dnp", "whois.nic.dnp");
    m.insert("doctor", "whois.nic.doctor");
    m.insert("dog", "whois.nic.dog");
    m.insert("domains", "whois.nic.domains");
    m.insert("dot", "whois.nic.dot");
    m.insert("download", "whois.nic.download");
    m.insert("dtv", "whois.nic.dtv");
    m.insert("dubai", "whois.nic.dubai");
    m.insert("durban", "whois.nic.durban");
    m.insert("dvag", "whois.nic.dvag");
    m.insert("dvr", "whois.nic.dvr");
    m.insert("earth", "whois.nic.earth");
    m.insert("eco", "whois.nic.eco");
    m.insert("edeka", "whois.nic.edeka");
    m.insert("edu", "whois.educause.edu");
    m.insert("education", "whois.nic.education");
    m.insert("email", "whois.nic.email");
    m.insert("emerck", "whois.nic.emerck");
    m.insert("energy", "whois.nic.energy");
    m.insert("engineer", "whois.nic.engineer");
    m.insert("engineering", "whois.nic.engineering");
    m.insert("enterprises", "whois.nic.enterprises");
    m.insert("epson", "whois.nic.epson");
    m.insert("equipment", "whois.nic.equipment");
    m.insert("ericsson", "whois.nic.ericsson");
    m.insert("erni", "whois.nic.erni");
    m.insert("estate", "whois.nic.estate");
    m.insert("eurovision", "whois.nic.eurovision");
    m.insert("eus", "whois.nic.eus");
    m.insert("events", "whois.nic.events");
    m.insert("exchange", "whois.nic.exchange");
    m.insert("expert", "whois.nic.expert");
    m.insert("exposed", "whois.nic.exposed");
    m.insert("express", "whois.nic.express");
    m.insert("extraspace", "whois.nic.extraspace");
    m.insert("fage", "whois.nic.fage");
    m.insert("fail", "whois.nic.fail");
    m.insert("fairwinds", "whois.nic.fairwinds");
    m.insert("faith", "whois.nic.faith");
    m.insert("family", "whois.nic.family");
    m.insert("fan", "whois.nic.fan");
    m.insert("fans", "whois.nic.fans");
    m.insert("farm", "whois.nic.farm");
    m.insert("fashion", "whois.nic.fashion");
    m.insert("fast", "whois.nic.fast");
    m.insert("fedex", "whois.nic.fedex");
    m.insert("feedback", "whois.registry.click");
    m.insert("ferrari", "whois.nic.ferrari");
    m.insert("fidelity", "whois.nic.fidelity");
    m.insert("fido", "whois.nic.fido");
    m.insert("film", "whois.nic.film");
    m.insert("final", "whois.gtlds.nic.br");
    m.insert("finance", "whois.nic.finance");
    m.insert("financial", "whois.nic.financial");
    m.insert("fire", "whois.nic.fire");
    m.insert("firestone", "whois.nic.firestone");
    m.insert("firmdale", "whois.nic.firmdale");
    m.insert("fish", "whois.nic.fish");
    m.insert("fishing", "whois.nic.fishing");
    m.insert("fit", "whois.nic.fit");
    m.insert("fitness", "whois.nic.fitness");
    m.insert("flights", "whois.nic.flights");
    m.insert("florist", "whois.nic.florist");
    m.insert("flowers", "whois.nic.flowers");
    m.insert("food", "whois.registry.click");
    m.insert("football", "whois.nic.football");
    m.insert("forex", "whois.nic.forex");
    m.insert("forsale", "whois.nic.forsale");
    m.insert("forum", "whois.registry.click");
    m.insert("foundation", "whois.nic.foundation");
    m.insert("fox", "whois.nic.fox");
    m.insert("free", "whois.nic.free");
    m.insert("fresenius", "whois.nic.fresenius");
    m.insert("frl", "whois.nic.frl");
    m.insert("frogans", "whois.nic.frogans");
    m.insert("fujitsu", "whois.nic.gmo");
    m.insert("fun", "whois.nic.fun");
    m.insert("fund", "whois.nic.fund");
    m.insert("furniture", "whois.nic.furniture");
    m.insert("futbol", "whois.nic.futbol");
    m.insert("fyi", "whois.nic.fyi");
    m.insert("gal", "whois.nic.gal");
    m.insert("gallery", "whois.nic.gallery");
    m.insert("gallo", "whois.nic.gallo");
    m.insert("gallup", "whois.nic.gallup");
    m.insert("game", "whois.nic.game");
    m.insert("games", "whois.nic.games");
    m.insert("garden", "whois.nic.garden");
    m.insert("gay", "whois.nic.gay");
    m.insert("gdn", "whois.nic.gdn");
    m.insert("gea", "whois.nic.gea");
    m.insert("gent", "whois.nic.gent");
    m.insert("genting", "whois.nic.genting");
    m.insert("george", "whois.nic.george");
    m.insert("ggee", "whois.nic.ggee");
    m.insert("gift", "whois.registry.gift");
    m.insert("gifts", "whois.nic.gifts");
    m.insert("gives", "whois.nic.gives");
    m.insert("giving", "whois.nic.giving");
    m.insert("glass", "whois.nic.glass");
    m.insert("global", "whois.nic.global");
    m.insert("globo", "whois.gtlds.nic.br");
    m.insert("gmbh", "whois.nic.gmbh");
    m.insert("gmo", "whois.nic.gmo");
    m.insert("gmx", "whois.nic.gmx");
    m.insert("godaddy", "whois.nic.godaddy");
    m.insert("gold", "whois.nic.gold");
    m.insert("goldpoint", "whois.nic.goldpoint");
    m.insert("golf", "whois.nic.golf");
    m.insert("goodyear", "whois.nic.goodyear");
    m.insert("gop", "whois.nic.gop");
    m.insert("got", "whois.nic.got");
    m.insert("gov", "whois.nic.gov");
    m.insert("graphics", "whois.nic.graphics");
    m.insert("gratis", "whois.nic.gratis");
    m.insert("green", "whois.nic.green");
    m.insert("gripe", "whois.nic.gripe");
    m.insert("grocery", "whois.nic.grocery");
    m.insert("group", "whois.nic.group");
    m.insert("gucci", "whois.nic.gucci");
    m.insert("guide", "whois.nic.guide");
    m.insert("guitars", "whois.nic.guitars");
    m.insert("guru", "whois.nic.guru");
    m.insert("hair", "whois.nic.hair");
    m.insert("hamburg", "whois.nic.hamburg");
    m.insert("haus", "whois.nic.haus");
    m.insert("hdfc", "whois.nic.hdfc");
    m.insert("hdfcbank", "whois.nic.hdfcbank");
    m.insert("healthcare", "whois.nic.healthcare");
    m.insert("help", "whois.nic.help");
    m.insert("helsinki", "whois.nic.helsinki");
    m.insert("hermes", "whois.nic.hermes");
    m.insert("hiphop", "whois.nic.hiphop");
    m.insert("hisamitsu", "whois.nic.gmo");
    m.insert("hitachi", "whois.nic.gmo");
    m.insert("hiv", "whois.registry.click");
    m.insert("hkt", "whois.nic.hkt");
    m.insert("hockey", "whois.nic.hockey");
    m.insert("holdings", "whois.nic.holdings");
    m.insert("holiday", "whois.nic.holiday");
    m.insert("homedepot", "whois.nic.homedepot");
    m.insert("homes", "whois.nic.homes");
    m.insert("honda", "whois.nic.honda");
    m.insert("horse", "whois.nic.horse");
    m.insert("hospital", "whois.nic.hospital");
    m.insert("host", "whois.nic.host");
    m.insert("hosting", "whois.nic.hosting");
    m.insert("hot", "whois.nic.hot");
    m.insert("hotels", "whois.nic.hotels");
    m.insert("hotmail", "whois.nic.hotmail");
    m.insert("house", "whois.nic.house");
    m.insert("hughes", "whois.nic.hughes");
    m.insert("hyundai", "whois.nic.hyundai");
    m.insert("ibm", "whois.nic.ibm");
    m.insert("icbc", "whois.nic.icbc");
    m.insert("ice", "whois.nic.ice");
    m.insert("icu", "whois.nic.icu");
    m.insert("ifm", "whois.nic.ifm");
    m.insert("ikano", "whois.nic.ikano");
    m.insert("imamat", "whois.nic.imamat");
    m.insert("imdb", "whois.nic.imdb");
    m.insert("immo", "whois.nic.immo");
    m.insert("immobilien", "whois.nic.immobilien");
    m.insert("inc", "whois.nic.inc");
    m.insert("industries", "whois.nic.industries");
    m.insert("infiniti", "whois.nic.gmo");
    m.insert("info", "whois.nic.info");
    m.insert("ink", "whois.nic.ink");
    m.insert("institute", "whois.nic.institute");
    m.insert("insurance", "whois.nic.insurance");
    m.insert("insure", "whois.nic.insure");
    m.insert("int", "whois.iana.org");
    m.insert("international", "whois.nic.international");
    m.insert("investments", "whois.nic.investments");
    m.insert("irish", "whois.nic.irish");
    m.insert("ismaili", "whois.nic.ismaili");
    m.insert("ist", "whois.nic.ist");
    m.insert("istanbul", "whois.nic.istanbul");
    m.insert("itv", "whois.nic.itv");
    m.insert("jaguar", "whois.nic.jaguar");
    m.insert("java", "whois.nic.java");
    m.insert("jcb", "whois.nic.gmo");
    m.insert("jeep", "whois.nic.jeep");
    m.insert("jetzt", "whois.nic.jetzt");
    m.insert("jewelry", "whois.nic.jewelry");
    m.insert("jio", "whois.nic.jio");
    m.insert("jll", "whois.nic.jll");
    m.insert("jobs", "whois.nic.jobs");
    m.insert("joburg", "whois.nic.joburg");
    m.insert("jot", "whois.nic.jot");
    m.insert("joy", "whois.nic.joy");
    m.insert("jprs", "whois.nic.jprs");
    m.insert("juegos", "whois.uniregistry.net");
    m.insert("juniper", "whois.nic.juniper");
    m.insert("kaufen", "whois.nic.kaufen");
    m.insert("kddi", "whois.nic.kddi");
    m.insert("kerryhotels", "whois.nic.kerryhotels");
    m.insert("kerryproperties", "whois.nic.kerryproperties");
    m.insert("kfh", "whois.nic.kfh");
    m.insert("kia", "whois.nic.kia");
    m.insert("kids", "whois.nic.kids");
    m.insert("kim", "whois.nic.kim");
    m.insert("kindle", "whois.nic.kindle");
    m.insert("kitchen", "whois.nic.kitchen");
    m.insert("kiwi", "whois.nic.kiwi");
    m.insert("koeln", "whois.ryce-rsp.com");
    m.insert("komatsu", "whois.nic.komatsu");
    m.insert("kosher", "whois.nic.kosher");
    m.insert("krd", "whois.nic.krd");
    m.insert("kuokgroup", "whois.nic.kuokgroup");
    m.insert("kyoto", "whois.nic.kyoto");
    m.insert("lacaixa", "whois.nic.lacaixa");
    m.insert("lamborghini", "whois.nic.lamborghini");
    m.insert("lamer", "whois.nic.lamer");
    m.insert("land", "whois.nic.land");
    m.insert("landrover", "whois.nic.landrover");
    m.insert("lasalle", "whois.nic.lasalle");
    m.insert("lat", "whois.nic.lat");
    m.insert("latino", "whois.nic.latino");
    m.insert("latrobe", "whois.nic.latrobe");
    m.insert("law", "whois.nic.law");
    m.insert("lawyer", "whois.nic.lawyer");
    m.insert("lds", "whois.nic.lds");
    m.insert("lease", "whois.nic.lease");
    m.insert("leclerc", "whois.nic.leclerc");
    m.insert("lefrak", "whois.nic.lefrak");
    m.insert("legal", "whois.nic.legal");
    m.insert("lego", "whois.nic.lego");
    m.insert("lexus", "whois.nic.lexus");
    m.insert("lgbt", "whois.nic.lgbt");
    m.insert("lidl", "whois.nic.lidl");
    m.insert("life", "whois.nic.life");
    m.insert("lifeinsurance", "whois.nic.lifeinsurance");
    m.insert("lifestyle", "whois.registry.click");
    m.insert("lighting", "whois.nic.lighting");
    m.insert("like", "whois.nic.like");
    m.insert("limited", "whois.nic.limited");
    m.insert("limo", "whois.nic.limo");
    m.insert("link", "whois.uniregistry.net");
    m.insert("live", "whois.nic.live");
    m.insert("living", "whois.registry.click");
    m.insert("llc", "whois.nic.llc");
    m.insert("llp", "whois.nic.llp");
    m.insert("loan", "whois.nic.loan");
    m.insert("loans", "whois.nic.loans");
    m.insert("locker", "whois.nic.locker");
    m.insert("locus", "whois.nic.locus");
    m.insert("lol", "whois.nic.lol");
    m.insert("london", "whois.nic.london");
    m.insert("lotte", "whois.nic.lotte");
    m.insert("lotto", "whois.nic.lotto");
    m.insert("love", "whois.nic.love");
    m.insert("lpl", "whois.nic.lpl");
    m.insert("lplfinancial", "whois.nic.lplfinancial");
    m.insert("ltd", "whois.nic.ltd");
    m.insert("ltda", "whois.nic.ltda");
    m.insert("lundbeck", "whois.nic.lundbeck");
    m.insert("luxe", "whois.nic.luxe");
    m.insert("luxury", "whois.nic.luxury");
    m.insert("madrid", "whois.nic.madrid");
    m.insert("maif", "whois.nic.maif");
    m.insert("maison", "whois.nic.maison");
    m.insert("makeup", "whois.nic.makeup");
    m.insert("man", "whois.nic.man");
    m.insert("management", "whois.nic.management");
    m.insert("mango", "whois.nic.mango");
    m.insert("market", "whois.nic.market");
    m.insert("marketing", "whois.nic.marketing");
    m.insert("markets", "whois.nic.markets");
    m.insert("marriott", "whois.nic.marriott");
    m.insert("mba", "whois.nic.mba");
    m.insert("mckinsey", "whois.nic.mckinsey");
    m.insert("med", "whois.nic.med");
    m.insert("media", "whois.nic.media");
    m.insert("melbourne", "whois.nic.melbourne");
    m.insert("memorial", "whois.nic.memorial");
    m.insert("men", "whois.nic.men");
    m.insert("menu", "whois.nic.menu");
    m.insert("merck", "whois.nic.merck");
    m.insert("merckmsd", "whois.nic.merckmsd");
    m.insert("miami", "whois.nic.miami");
    m.insert("microsoft", "whois.nic.microsoft");
    m.insert("mini", "whois.nic.mini");
    m.insert("mit", "whois.nic.mit");
    m.insert("mitsubishi", "whois.nic.gmo");
    m.insert("mls", "whois.nic.mls");
    m.insert("mma", "whois.nic.mma");
    m.insert("mobi", "whois.nic.mobi");
    m.insert("mobile", "whois.nic.mobile");
    m.insert("moda", "whois.nic.moda");
    m.insert("moe", "whois.nic.moe");
    m.insert("moi", "whois.nic.moi");
    m.insert("mom", "whois.nic.mom");
    m.insert("monash", "whois.nic.monash");
    m.insert("money", "whois.nic.money");
    m.insert("monster", "whois.nic.monster");
    m.insert("mormon", "whois.nic.mormon");
    m.insert("mortgage", "whois.nic.mortgage");
    m.insert("moscow", "whois.nic.moscow");
    m.insert("moto", "whois.nic.moto");
    m.insert("motorcycles", "whois.nic.motorcycles");
    m.insert("movie", "whois.nic.movie");
    m.insert("msd", "whois.nic.msd");
    m.insert("mtn", "whois.nic.mtn");
    m.insert("mtr", "whois.nic.mtr");
    m.insert("museum", "whois.nic.museum");
    m.insert("music", "whois.registryservices.music");
    m.insert("nab", "whois.nic.nab");
    m.insert("nagoya", "whois.nic.nagoya");
    m.insert("name", "whois.nic.name");
    m.insert("navy", "whois.nic.navy");
    m.insert("nec", "whois.nic.nec");
    m.insert("net", "whois.verisign-grs.com");
    m.insert("netbank", "whois.nic.netbank");
    m.insert("network", "whois.nic.network");
    m.insert("news", "whois.nic.news");
    m.insert("next", "whois.nic.next");
    m.insert("nextdirect", "whois.nic.nextdirect");
    m.insert("ngo", "whois.nic.ngo");
    m.insert("nhk", "whois.nic.nhk");
    m.insert("nico", "whois.nic.nico");
    m.insert("nikon", "whois.nic.nikon");
    m.insert("ninja", "whois.nic.ninja");
    m.insert("nissan", "whois.nic.gmo");
    m.insert("nissay", "whois.nic.nissay");
    m.insert("nokia", "whois.nic.nokia");
    m.insert("norton", "whois.nic.norton");
    m.insert("now", "whois.nic.now");
    m.insert("nowruz", "whois.nic.nowruz");
    m.insert("nowtv", "whois.nic.nowtv");
    m.insert("nra", "whois.nic.nra");
    m.insert("nrw", "whois.nic.nrw");
    m.insert("ntt", "whois.nic.ntt");
    m.insert("nyc", "whois.nic.nyc");
    m.insert("obi", "whois.nic.obi");
    m.insert("observer", "whois.nic.observer");
    m.insert("office", "whois.nic.office");
    m.insert("okinawa", "whois.nic.okinawa");
    m.insert("olayan", "whois.nic.olayan");
    m.insert("olayangroup", "whois.nic.olayangroup");
    m.insert("ollo", "whois.nic.ollo");
    m.insert("omega", "whois.nic.omega");
    m.insert("one", "whois.nic.one");
    m.insert("ong", "whois.nic.ong");
    m.insert("onl", "whois.nic.onl");
    m.insert("online", "whois.nic.online");
    m.insert("ooo", "whois.nic.ooo");
    m.insert("open", "whois.nic.open");
    m.insert("oracle", "whois.nic.oracle");
    m.insert("orange", "whois.nic.orange");
    m.insert("org", "whois.publicinterestregistry.org");
    m.insert("organic", "whois.nic.organic");
    m.insert("origins", "whois.nic.origins");
    m.insert("osaka", "whois.nic.osaka");
    m.insert("otsuka", "whois.nic.otsuka");
    m.insert("ott", "whois.nic.ott");
    m.insert("ovh", "whois.nic.ovh");
    m.insert("panasonic", "whois.nic.gmo");
    m.insert("paris", "whois.nic.paris");
    m.insert("pars", "whois.nic.pars");
    m.insert("partners", "whois.nic.partners");
    m.insert("parts", "whois.nic.parts");
    m.insert("party", "whois.nic.party");
    m.insert("pay", "whois.nic.pay");
    m.insert("pccw", "whois.nic.pccw");
    m.insert("pet", "whois.nic.pet");
    m.insert("philips", "whois.nic.philips");
    m.insert("phone", "whois.nic.phone");
    m.insert("photo", "whois.nic.photo");
    m.insert("photography", "whois.nic.photography");
    m.insert("photos", "whois.nic.photos");
    m.insert("physio", "whois.nic.physio");
    m.insert("pics", "whois.nic.pics");
    m.insert("pictet", "whois.nic.pictet");
    m.insert("pictures", "whois.nic.pictures");
    m.insert("pid", "whois.registry.click");
    m.insert("pin", "whois.nic.pin");
    m.insert("ping", "whois.nic.ping");
    m.insert("pink", "whois.nic.pink");
    m.insert("pioneer", "whois.nic.pioneer");
    m.insert("pizza", "whois.nic.pizza");
    m.insert("place", "whois.nic.place");
    m.insert("playstation", "whois.nic.playstation");
    m.insert("plumbing", "whois.nic.plumbing");
    m.insert("plus", "whois.nic.plus");
    m.insert("pnc", "whois.nic.pnc");
    m.insert("pohl", "whois.nic.pohl");
    m.insert("poker", "whois.nic.poker");
    m.insert("politie", "whois.nic.politie");
    m.insert("porn", "whois.nic.porn");
    m.insert("post", "whois.nic.post");
    m.insert("press", "whois.nic.press");
    m.insert("prime", "whois.nic.prime");
    m.insert("pro", "whois.nic.pro");
    m.insert("productions", "whois.nic.productions");
    m.insert("progressive", "whois.nic.progressive");
    m.insert("promo", "whois.nic.promo");
    m.insert("properties", "whois.nic.properties");
    m.insert("property", "whois.registry.click");
    m.insert("protection", "whois.nic.protection");
    m.insert("pub", "whois.nic.pub");
    m.insert("pwc", "whois.nic.pwc");
    m.insert("qpon", "whois.nic.qpon");
    m.insert("quebec", "whois.nic.quebec");
    m.insert("quest", "whois.nic.quest");
    m.insert("racing", "whois.nic.racing");
    m.insert("radio", "whois.nic.radio");
    m.insert("read", "whois.nic.read");
    m.insert("realestate", "whois.nic.realestate");
    m.insert("realtor", "whois.nic.realtor");
    m.insert("realty", "whois.nic.realty");
    m.insert("recipes", "whois.nic.recipes");
    m.insert("red", "whois.nic.red");
    m.insert("redumbrella", "whois.nic.redumbrella");
    m.insert("rehab", "whois.nic.rehab");
    m.insert("reise", "whois.nic.reise");
    m.insert("reisen", "whois.nic.reisen");
    m.insert("reit", "whois.nic.reit");
    m.insert("reliance", "whois.nic.reliance");
    m.insert("ren", "whois.nic.ren");
    m.insert("rent", "whois.nic.rent");
    m.insert("rentals", "whois.nic.rentals");
    m.insert("repair", "whois.nic.repair");
    m.insert("report", "whois.nic.report");
    m.insert("republican", "whois.nic.republican");
    m.insert("rest", "whois.nic.rest");
    m.insert("restaurant", "whois.nic.restaurant");
    m.insert("review", "whois.nic.review");
    m.insert("reviews", "whois.nic.reviews");
    m.insert("rexroth", "whois.nic.rexroth");
    m.insert("rich", "whois.nic.rich");
    m.insert("richardli", "whois.nic.richardli");
    m.insert("ricoh", "whois.nic.ricoh");
    m.insert("ril", "whois.nic.ril");
    m.insert("rio", "whois.gtlds.nic.br");
    m.insert("rip", "whois.nic.rip");
    m.insert("rocks", "whois.nic.rocks");
    m.insert("rodeo", "whois.nic.rodeo");
    m.insert("rogers", "whois.nic.rogers");
    m.insert("room", "whois.nic.room");
    m.insert("rugby", "whois.nic.rugby");
    m.insert("ruhr", "whois.nic.ruhr");
    m.insert("run", "whois.nic.run");
    m.insert("rwe", "whois.nic.rwe");
    m.insert("ryukyu", "whois.nic.ryukyu");
    m.insert("saarland", "whois.nic.saarland");
    m.insert("safe", "whois.nic.safe");
    m.insert("safety", "whois.nic.safety");
    m.insert("sakura", "whois.nic.sakura");
    m.insert("sale", "whois.nic.sale");
    m.insert("salon", "whois.nic.salon");
    m.insert("samsclub", "whois.nic.samsclub");
    m.insert("samsung", "whois.nic.samsung");
    m.insert("sandvik", "whois.nic.sandvik");
    m.insert("sandvikcoromant", "whois.nic.sandvikcoromant");
    m.insert("sanofi", "whois.nic.sanofi");
    m.insert("sap", "whois.nic.sap");
    m.insert("sarl", "whois.nic.sarl");
    m.insert("save", "whois.nic.save");
    m.insert("saxo", "whois.nic.saxo");
    m.insert("sbi", "whois.nic.sbi");
    m.insert("sbs", "whois.nic.sbs");
    m.insert("scb", "whois.nic.scb");
    m.insert("schaeffler", "whois.afilias-srs.net");
    m.insert("schmidt", "whois.nic.schmidt");
    m.insert("scholarships", "whois.nic.scholarships");
    m.insert("school", "whois.nic.school");
    m.insert("schule", "whois.nic.schule");
    m.insert("schwarz", "whois.nic.schwarz");
    m.insert("science", "whois.nic.science");
    m.insert("scot", "whois.nic.scot");
    m.insert("seat", "whois.nic.seat");
    m.insert("secure", "whois.nic.secure");
    m.insert("security", "whois.nic.security");
    m.insert("seek", "whois.nic.seek");
    m.insert("select", "whois.nic.select");
    m.insert("sener", "whois.nic.rwe");
    m.insert("services", "whois.nic.services");
    m.insert("seven", "whois.nic.seven");
    m.insert("sew", "whois.nic.sew");
    m.insert("sex", "whois.nic.sex");
    m.insert("sexy", "whois.registry.click");
    m.insert("sfr", "whois.nic.sfr");
    m.insert("shangrila", "whois.nic.shangrila");
    m.insert("sharp", "whois.nic.gmo");
    m.insert("shell", "whois.nic.shell");
    m.insert("shia", "whois.nic.shia");
    m.insert("shiksha", "whois.nic.shiksha");
    m.insert("shoes", "whois.nic.shoes");
    m.insert("shop", "whois.nic.shop");
    m.insert("shopping", "whois.nic.shopping");
    m.insert("shouji", "whois.teleinfo.cn");
    m.insert("show", "whois.nic.show");
    m.insert("silk", "whois.nic.silk");
    m.insert("sina", "whois.nic.sina");
    m.insert("singles", "whois.nic.singles");
    m.insert("site", "whois.nic.site");
    m.insert("ski", "whois.nic.ski");
    m.insert("skin", "whois.nic.skin");
    m.insert("sky", "whois.nic.sky");
    m.insert("skype", "whois.nic.skype");
    m.insert("sling", "whois.nic.sling");
    m.insert("smart", "whois.nic.smart");
    m.insert("smile", "whois.nic.smile");
    m.insert("sncf", "whois.nic.sncf");
    m.insert("soccer", "whois.nic.soccer");
    m.insert("social", "whois.nic.social");
    m.insert("softbank", "whois.nic.softbank");
    m.insert("software", "whois.nic.software");
    m.insert("solar", "whois.nic.solar");
    m.insert("solutions", "whois.nic.solutions");
    m.insert("song", "whois.nic.song");
    m.insert("sony", "whois.nic.sony");
    m.insert("spa", "whois.nic.spa");
    m.insert("space", "whois.nic.space");
    m.insert("sport", "whois.nic.sport");
    m.insert("spot", "whois.nic.spot");
    m.insert("srl", "whois.nic.srl");
    m.insert("stada", "whois.nic.stada");
    m.insert("star", "whois.nic.star");
    m.insert("statebank", "whois.nic.statebank");
    m.insert("stc", "whois.nic.stc");
    m.insert("stcgroup", "whois.nic.stcgroup");
    m.insert("stockholm", "whois.nic.stockholm");
    m.insert("storage", "whois.nic.storage");
    m.insert("store", "whois.nic.store");
    m.insert("stream", "whois.nic.stream");
    m.insert("studio", "whois.nic.studio");
    m.insert("study", "whois.nic.study");
    m.insert("style", "whois.nic.style");
    m.insert("sucks", "whois.nic.sucks");
    m.insert("supplies", "whois.nic.supplies");
    m.insert("supply", "whois.nic.supply");
    m.insert("support", "whois.nic.support");
    m.insert("surf", "whois.nic.surf");
    m.insert("surgery", "whois.nic.surgery");
    m.insert("suzuki", "whois.nic.suzuki");
    m.insert("swatch", "whois.nic.swatch");
    m.insert("swiss", "whois.nic.swiss");
    m.insert("sydney", "whois.nic.sydney");
    m.insert("systems", "whois.nic.systems");
    m.insert("tab", "whois.nic.tab");
    m.insert("taipei", "whois.nic.taipei");
    m.insert("talk", "whois.nic.talk");
    m.insert("taobao", "whois.nic.taobao");
    m.insert("tatamotors", "whois.nic.tatamotors");
    m.insert("tatar", "whois.nic.tatar");
    m.insert("tattoo", "whois.nic.tattoo");
    m.insert("tax", "whois.nic.tax");
    m.insert("taxi", "whois.nic.taxi");
    m.insert("tci", "whois.nic.tci");
    m.insert("tdk", "whois.nic.tdk");
    m.insert("team", "whois.nic.team");
    m.insert("tech", "whois.nic.tech");
    m.insert("technology", "whois.nic.technology");
    m.insert("tel", "whois.nic.tel");
    m.insert("temasek", "whois.nic.temasek");
    m.insert("tennis", "whois.nic.tennis");
    m.insert("teva", "whois.nic.teva");
    m.insert("thd", "whois.nic.thd");
    m.insert("theater", "whois.nic.theater");
    m.insert("theatre", "whois.nic.theatre");
    m.insert("tiaa", "whois.nic.tiaa");
    m.insert("tickets", "whois.nic.tickets");
    m.insert("tienda", "whois.nic.tienda");
    m.insert("tips", "whois.nic.tips");
    m.insert("tires", "whois.nic.tires");
    m.insert("tirol", "whois.nic.tirol");
    m.insert("tmall", "whois.nic.tmall");
    m.insert("today", "whois.nic.today");
    m.insert("tokyo", "whois.nic.tokyo");
    m.insert("tools", "whois.nic.tools");
    m.insert("top", "whois.nic.top");
    m.insert("toray", "whois.nic.toray");
    m.insert("toshiba", "whois.nic.toshiba");
    m.insert("total", "whois.nic.total");
    m.insert("tours", "whois.nic.tours");
    m.insert("town", "whois.nic.town");
    m.insert("toyota", "whois.nic.toyota");
    m.insert("toys", "whois.nic.toys");
    m.insert("trade", "whois.nic.trade");
    m.insert("trading", "whois.nic.trading");
    m.insert("training", "whois.nic.training");
    m.insert("travel", "whois.nic.travel");
    m.insert("travelers", "whois.nic.travelers");
    m.insert("travelersinsurance", "whois.nic.travelersinsurance");
    m.insert("trust", "whois.registry.click");
    m.insert("trv", "whois.nic.trv");
    m.insert("tube", "whois.nic.tube");
    m.insert("tui", "whois.nic.tui");
    m.insert("tunes", "whois.nic.tunes");
    m.insert("tushu", "whois.nic.tushu");
    m.insert("tvs", "whois.nic.tvs");
    m.insert("ubank", "whois.nic.ubank");
    m.insert("ubs", "whois.nic.ubs");
    m.insert("unicom", "whois.nic.unicom");
    m.insert("university", "whois.nic.university");
    m.insert("uno", "whois.nic.uno");
    m.insert("uol", "whois.gtlds.nic.br");
    m.insert("ups", "whois.nic.ups");
    m.insert("vacations", "whois.nic.vacations");
    m.insert("vana", "whois.registry.click");
    m.insert("vanguard", "whois.nic.vanguard");
    m.insert("vegas", "whois.nic.vegas");
    m.insert("ventures", "whois.nic.ventures");
    m.insert("verisign", "whois.nic.verisign");
    m.insert("versicherung", "whois.nic.versicherung");
    m.insert("vet", "whois.nic.vet");
    m.insert("viajes", "whois.nic.viajes");
    m.insert("video", "whois.nic.video");
    m.insert("vig", "whois.nic.vig");
    m.insert("viking", "whois.nic.viking");
    m.insert("villas", "whois.nic.villas");
    m.insert("vin", "whois.nic.vin");
    m.insert("vip", "whois.nic.vip");
    m.insert("virgin", "whois.nic.virgin");
    m.insert("visa", "whois.nic.visa");
    m.insert("vision", "whois.nic.vision");
    m.insert("viva", "whois.nic.viva");
    m.insert("vodka", "whois.nic.vodka");
    m.insert("volvo", "whois.nic.volvo");
    m.insert("vote", "whois.nic.vote");
    m.insert("voting", "whois.nic.voting");
    m.insert("voto", "whois.nic.voto");
    m.insert("voyage", "whois.nic.voyage");
    m.insert("walmart", "whois.nic.walmart");
    m.insert("walter", "whois.nic.walter");
    m.insert("wang", "whois.gtld.zdns.cn");
    m.insert("wanggou", "whois.nic.wanggou");
    m.insert("watch", "whois.nic.watch");
    m.insert("watches", "whois.nic.watches");
    m.insert("webcam", "whois.nic.webcam");
    m.insert("weber", "whois.nic.weber");
    m.insert("website", "whois.nic.website");
    m.insert("wed", "whois.nic.wed");
    m.insert("wedding", "whois.nic.wedding");
    m.insert("weibo", "whois.nic.weibo");
    m.insert("weir", "whois.nic.weir");
    m.insert("whoswho", "whois.nic.whoswho");
    m.insert("wien", "whois.nic.wien");
    m.insert("wiki", "whois.nic.wiki");
    m.insert("win", "whois.nic.win");
    m.insert("windows", "whois.nic.windows");
    m.insert("wine", "whois.nic.wine");
    m.insert("wme", "whois.nic.wme");
    m.insert("woodside", "whois.nic.woodside");
    m.insert("work", "whois.nic.work");
    m.insert("works", "whois.nic.works");
    m.insert("world", "whois.nic.world");
    m.insert("wow", "whois.nic.wow");
    m.insert("wtc", "whois.nic.wtc");
    m.insert("wtf", "whois.nic.wtf");
    m.insert("xbox", "whois.nic.xbox");
    m.insert("xerox", "whois.nic.xerox");
    m.insert("xihuan", "whois.teleinfo.cn");
    m.insert("xin", "whois.nic.xin");
    m.insert("xxx", "whois.nic.xxx");
    m.insert("xyz", "whois.nic.xyz");
    m.insert("yachts", "whois.nic.yachts");
    m.insert("yahoo", "whois.nic.yahoo");
    m.insert("yamaxun", "whois.nic.yamaxun");
    m.insert("yandex", "whois.nic.yandex");
    m.insert("yodobashi", "whois.nic.gmo");
    m.insert("yoga", "whois.nic.yoga");
    m.insert("yokohama", "whois.nic.yokohama");
    m.insert("you", "whois.nic.you");
    m.insert("yun", "whois.teleinfo.cn");
    m.insert("zappos", "whois.nic.zappos");
    m.insert("zara", "whois.nic.zara");
    m.insert("zero", "whois.nic.zero");
    m.insert("zone", "whois.nic.zone");
    m.insert("zuerich", "whois.nic.zuerich");

    // ============================================================
    // Country Code TLDs (ccTLDs)
    // ============================================================
    m.insert("ac", "whois.nic.ac");
    m.insert("ad", "whois.nic.ad");
    m.insert("ae", "whois.aeda.net.ae");
    m.insert("af", "whois.nic.af");
    m.insert("ag", "whois.nic.ag");
    m.insert("ai", "whois.nic.ai");
    m.insert("am", "whois.amnic.net");
    m.insert("ar", "whois.nic.ar");
    m.insert("as", "whois.nic.as");
    m.insert("at", "whois.nic.at");
    m.insert("au", "whois.auda.org.au");
    m.insert("aw", "whois.nic.aw");
    m.insert("ax", "whois.ax");
    m.insert("be", "whois.dns.be");
    m.insert("bf", "whois.registre.bf");
    m.insert("bg", "whois.register.bg");
    m.insert("bh", "whois.nic.bh");
    m.insert("bi", "whois1.nic.bi");
    m.insert("bj", "whois.nic.bj");
    m.insert("bm", "whois.nic.bm");
    m.insert("bn", "whois.bnnic.bn");
    m.insert("bo", "whois.nic.bo");
    m.insert("br", "whois.registro.br");
    m.insert("bw", "whois.nic.net.bw");
    m.insert("by", "whois.cctld.by");
    m.insert("bz", "whois.afilias-grs.info");
    m.insert("ca", "whois.cira.ca");
    m.insert("cc", "ccwhois.verisign-grs.com");
    m.insert("cd", "whois.nic.cd");
    m.insert("cf", "whois.dot.cf");
    m.insert("ch", "whois.nic.ch");
    m.insert("ci", "whois.nic.ci");
    m.insert("cl", "whois.nic.cl");
    m.insert("cm", "whois.nic.cm");
    m.insert("cn", "whois.cnnic.cn");
    m.insert("co", "whois.registry.co");
    m.insert("cr", "whois.nic.cr");
    m.insert("cv", "whois.nic.cv");
    m.insert("cx", "whois.nic.cx");
    m.insert("cz", "whois.nic.cz");
    m.insert("de", "whois.denic.de");
    m.insert("dk", "whois.punktum.dk");
    m.insert("dm", "whois.dmdomains.dm");
    m.insert("do", "whois.nic.do");
    m.insert("dz", "whois.nic.dz");
    m.insert("ec", "whois.nic.ec");
    m.insert("ee", "whois.tld.ee");
    m.insert("es", "whois.nic.es");
    m.insert("eu", "whois.eu");
    m.insert("fi", "whois.fi");
    m.insert("fj", "www.whois.fj");
    m.insert("fm", "whois.nic.fm");
    m.insert("fo", "whois.nic.fo");
    m.insert("fr", "whois.nic.fr");
    m.insert("gd", "whois.nic.gd");
    m.insert("ge", "whois.nic.ge");
    m.insert("gf", "whois.mediaserv.net");
    m.insert("gg", "whois.gg");
    m.insert("gh", "whois.nic.gh");
    m.insert("gi", "whois.identitydigital.services");
    m.insert("gl", "whois.nic.gl");
    m.insert("gn", "whois.ande.gov.gn");
    m.insert("gp", "whois.nic.gp");
    m.insert("gq", "whois.dominio.gq");
    m.insert("gs", "whois.nic.gs");
    m.insert("gy", "whois.registry.gy");
    m.insert("hk", "whois.hkirc.hk");
    m.insert("hm", "whois.registry.hm");
    m.insert("hn", "whois.nic.hn");
    m.insert("hr", "whois.dns.hr");
    m.insert("ht", "whois.nic.ht");
    m.insert("hu", "whois.nic.hu");
    m.insert("id", "whois.id");
    m.insert("ie", "whois.weare.ie");
    m.insert("il", "whois.isoc.org.il");
    m.insert("im", "whois.nic.im");
    m.insert("in", "whois.nixiregistry.in");
    m.insert("io", "whois.nic.io");
    m.insert("iq", "whois.cmc.iq");
    m.insert("ir", "whois.nic.ir");
    m.insert("is", "whois.isnic.is");
    m.insert("it", "whois.nic.it");
    m.insert("je", "whois.je");
    m.insert("jp", "whois.jprs.jp");
    m.insert("ke", "whois.kenic.or.ke");
    m.insert("kg", "whois.kg");
    m.insert("ki", "whois.nic.ki");
    m.insert("kn", "whois.nic.kn");
    m.insert("kr", "whois.kr");
    m.insert("kw", "whois.nic.kw");
    m.insert("ky", "whois.kyregistry.ky");
    m.insert("kz", "whois.nic.kz");
    m.insert("la", "whois.nic.la");
    m.insert("lb", "whois.lbdr.org.lb");
    m.insert("lc", "whois.afilias-grs.info");
    m.insert("li", "whois.nic.li");
    m.insert("lk", "whois.nic.lk");
    m.insert("ls", "whois.nic.ls");
    m.insert("lt", "whois.domreg.lt");
    m.insert("lu", "whois.dns.lu");
    m.insert("lv", "whois.nic.lv");
    m.insert("ly", "whois.nic.ly");
    m.insert("ma", "whois.registre.ma");
    m.insert("mc", "whois.nic.mc");
    m.insert("md", "whois.nic.md");
    m.insert("me", "whois.nic.me");
    m.insert("mg", "whois.nic.mg");
    m.insert("mk", "whois.marnet.mk");
    m.insert("ml", "whois.nic.ml");
    m.insert("mm", "whois.registry.gov.mm");
    m.insert("mn", "whois.nic.mn");
    m.insert("mo", "whois.monic.mo");
    m.insert("mq", "whois.mediaserv.net");
    m.insert("mr", "whois.nic.mr");
    m.insert("ms", "whois.nic.ms");
    m.insert("mt", "whois.nic.org.mt");
    m.insert("mu", "whois.tld.mu");
    m.insert("mw", "whois.nic.mw");
    m.insert("mx", "whois.mx");
    m.insert("my", "whois.mynic.my");
    m.insert("mz", "whois.nic.mz");
    m.insert("nc", "whois.nc");
    m.insert("nf", "whois.nic.nf");
    m.insert("ng", "whois.nic.net.ng");
    m.insert("nl", "whois.domain-registry.nl");
    m.insert("no", "whois.norid.no");
    m.insert("nu", "whois.iis.nu");
    m.insert("nz", "whois.irs.net.nz");
    m.insert("om", "whois.registry.om");
    m.insert("pe", "kero.yachay.pe");
    m.insert("pf", "whois.registry.pf");
    m.insert("pg", "whois.nic.pg");
    m.insert("pk", "whois.pknic.net.pk");
    m.insert("pl", "whois.dns.pl");
    m.insert("pm", "whois.nic.pm");
    m.insert("pr", "whois.afilias-srs.net");
    m.insert("ps", "whois.pnina.ps");
    m.insert("pt", "whois.dns.pt");
    m.insert("pw", "whois.nic.pw");
    m.insert("qa", "whois.registry.qa");
    m.insert("re", "whois.nic.re");
    m.insert("ro", "whois.rotld.ro");
    m.insert("rs", "whois.rnids.rs");
    m.insert("ru", "whois.tcinet.ru");
    m.insert("rw", "whois.ricta.org.rw");
    m.insert("sa", "whois.nic.net.sa");
    m.insert("sb", "whois.nic.net.sb");
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
    m.insert("sr", "whois.sr");
    m.insert("ss", "whois.nic.ss");
    m.insert("st", "whois.nic.st");
    m.insert("su", "whois.tcinet.ru");
    m.insert("sx", "whois.sx");
    m.insert("sy", "whois.tld.sy");
    m.insert("tc", "whois.nic.tc");
    m.insert("td", "whois.nic.td");
    m.insert("tf", "whois.nic.tf");
    m.insert("tg", "whois.nic.tg");
    m.insert("th", "whois.thnic.co.th");
    m.insert("tk", "whois.dot.tk");
    m.insert("tl", "whois.nic.tl");
    m.insert("tm", "whois.nic.tm");
    m.insert("tn", "whois.ati.tn");
    m.insert("to", "whois.tonicregistry.to");
    m.insert("tr", "whois.trabis.gov.tr");
    m.insert("tv", "whois.nic.tv");
    m.insert("tw", "whois.twnic.net.tw");
    m.insert("tz", "whois.tznic.or.tz");
    m.insert("ua", "whois.ua");
    m.insert("ug", "whois.co.ug");
    m.insert("uk", "whois.nic.uk");
    m.insert("us", "whois.nic.us");
    m.insert("uy", "whois.nic.org.uy");
    m.insert("uz", "whois.cctld.uz");
    m.insert("vc", "whois.identitydigital.services");
    m.insert("ve", "whois.nic.ve");
    m.insert("vg", "whois.nic.vg");
    m.insert("vi", "virgil.nic.vi");
    m.insert("vu", "whois.dnrs.vu");
    m.insert("wf", "whois.nic.wf");
    m.insert("ws", "whois.website.ws");
    m.insert("ye", "whois.y.net.ye");
    m.insert("yt", "whois.nic.yt");
    m.insert("zm", "whois.zicta.zm");

    // ============================================================
    // Internationalized TLDs — punycode form
    // ============================================================
    m.insert("xn--11b4c3d", "whois.nic.xn--11b4c3d");
    m.insert("xn--1ck2e1b", "whois.nic.xn--1ck2e1b");
    m.insert("xn--1qqw23a", "whois.ngtld.cn");
    m.insert("xn--2scrj9c", "whois.nixiregistry.in");
    m.insert("xn--30rr7y", "whois.gtld.zdns.cn");
    m.insert("xn--3bst00m", "whois.gtld.zdns.cn");
    m.insert("xn--3ds443g", "whois.teleinfo.cn");
    m.insert("xn--3e0b707e", "whois.kr");
    m.insert("xn--3hcrj9c", "whois.nixiregistry.in");
    m.insert("xn--3pxu8k", "whois.nic.xn--3pxu8k");
    m.insert("xn--42c2d9a", "whois.nic.xn--42c2d9a");
    m.insert("xn--45br5cyl", "whois.nixiregistry.in");
    m.insert("xn--45brj9c", "whois.nixiregistry.in");
    m.insert("xn--45q11c", "whois.gtld.zdns.cn");
    m.insert("xn--4dbrk0ce", "whois.isoc.org.il");
    m.insert("xn--4gbrim", "whois.nic.xn--4gbrim");
    m.insert("xn--55qw42g", "whois.conac.cn");
    m.insert("xn--55qx5d", "whois.ngtld.cn");
    m.insert("xn--5su34j936bgsg", "whois.nic.xn--5su34j936bgsg");
    m.insert("xn--5tzm5g", "whois.nic.xn--5tzm5g");
    m.insert("xn--6frz82g", "whois.nic.xn--6frz82g");
    m.insert("xn--6qq986b3xl", "whois.gtld.zdns.cn");
    m.insert("xn--80adxhks", "whois.nic.xn--80adxhks");
    m.insert("xn--80ao21a", "whois.nic.kz");
    m.insert("xn--80aqecdr1a", "whois.nic.xn--80aqecdr1a");
    m.insert("xn--80asehdb", "whois.nic.xn--80asehdb");
    m.insert("xn--80aswg", "whois.nic.xn--80aswg");
    m.insert("xn--8y0a063a", "whois.nic.xn--8y0a063a");
    m.insert("xn--90a3ac", "whois.rnids.rs");
    m.insert("xn--90ae", "whois.imena.bg");
    m.insert("xn--90ais", "whois.cctld.by");
    m.insert("xn--9dbq2a", "whois.nic.xn--9dbq2a");
    m.insert("xn--9et52u", "whois.gtld.zdns.cn");
    m.insert("xn--9krt00a", "whois.nic.xn--9krt00a");
    m.insert("xn--b4w605ferd", "whois.nic.xn--b4w605ferd");
    m.insert("xn--bck1b9a5dre4c", "whois.nic.xn--bck1b9a5dre4c");
    m.insert("xn--c1avg", "whois.nic.xn--c1avg");
    m.insert("xn--c2br7g", "whois.nic.xn--c2br7g");
    m.insert("xn--cck2b3b", "whois.nic.xn--cck2b3b");
    m.insert("xn--cckwcxetd", "whois.nic.xn--cckwcxetd");
    m.insert("xn--cg4bki", "whois.kr");
    m.insert("xn--clchc0ea0b2g2a9gcd", "whois.ta.sgnic.sg");
    m.insert("xn--czrs0t", "whois.nic.xn--czrs0t");
    m.insert("xn--czru2d", "whois.gtld.zdns.cn");
    m.insert("xn--d1acj3b", "whois.nic.xn--d1acj3b");
    m.insert("xn--d1alf", "whois.marnet.mk");
    m.insert("xn--e1a4c", "whois.eu");
    m.insert("xn--eckvdtc9d", "whois.nic.xn--eckvdtc9d");
    m.insert("xn--efvy88h", "whois.gtld.zdns.cn");
    m.insert("xn--fct429k", "whois.nic.xn--fct429k");
    m.insert("xn--fhbei", "whois.nic.xn--fhbei");
    m.insert("xn--fiq228c5hs", "whois.teleinfo.cn");
    m.insert("xn--fiq64b", "whois.gtld.zdns.cn");
    m.insert("xn--fiqs8s", "whois.cnnic.cn");
    m.insert("xn--fiqz9s", "whois.cnnic.cn");
    m.insert("xn--fjq720a", "whois.nic.xn--fjq720a");
    m.insert("xn--fpcrj9c3d", "whois.nixiregistry.in");
    m.insert("xn--fzc2c9e2c", "whois.nic.lk");
    m.insert("xn--fzys8d69uvgm", "whois.nic.xn--fzys8d69uvgm");
    m.insert("xn--g2xx48c", "whois.nic.xn--g2xx48c");
    m.insert("xn--gckr3f0f", "whois.nic.xn--gckr3f0f");
    m.insert("xn--gecrj9c", "whois.nixiregistry.in");
    m.insert("xn--gk3at1e", "whois.nic.xn--gk3at1e");
    m.insert("xn--h2breg3eve", "whois.nixiregistry.in");
    m.insert("xn--h2brj9c", "whois.nixiregistry.in");
    m.insert("xn--h2brj9c8c", "whois.nixiregistry.in");
    m.insert("xn--hxt814e", "whois.gtld.zdns.cn");
    m.insert("xn--i1b6b1a6a2e", "whois.nic.xn--i1b6b1a6a2e");
    m.insert("xn--io0a7i", "whois.ngtld.cn");
    m.insert("xn--j1aef", "whois.nic.xn--j1aef");
    m.insert("xn--j1amh", "whois.dotukr.com");
    m.insert("xn--j6w193g", "whois.hkirc.hk");
    m.insert("xn--jlq480n2rg", "whois.nic.xn--jlq480n2rg");
    m.insert("xn--jvr189m", "whois.nic.xn--jvr189m");
    m.insert("xn--kcrx77d1x4a", "whois.nic.xn--kcrx77d1x4a");
    m.insert("xn--kprw13d", "whois.twnic.net.tw");
    m.insert("xn--kpry57d", "whois.twnic.net.tw");
    m.insert("xn--kput3i", "whois.nic.xn--kput3i");
    m.insert("xn--l1acc", "whois.mn");
    m.insert("xn--lgbbat1ad8j", "whois.nic.dz");
    m.insert("xn--mgb9awbf", "whois.registry.om");
    m.insert("xn--mgba3a4f16a", "whois.nic.ir");
    m.insert("xn--mgba7c0bbn0a", "whois.nic.xn--mgba7c0bbn0a");
    m.insert("xn--mgbaam7a8h", "whois.aeda.net.ae");
    m.insert("xn--mgbab2bd", "whois.nic.xn--mgbab2bd");
    m.insert("xn--mgbah1a3hjkrd", "whois.nic.mr");
    m.insert("xn--mgbbh1a", "whois.nixiregistry.in");
    m.insert("xn--mgbbh1a71e", "whois.nixiregistry.in");
    m.insert("xn--mgbca7dzdo", "whois.nic.xn--mgbca7dzdo");
    m.insert("xn--mgberp4a5d4ar", "whois.nic.net.sa");
    m.insert("xn--mgbgu82a", "whois.nixiregistry.in");
    m.insert("xn--mgbi4ecexp", "whois.nic.xn--mgbi4ecexp");
    m.insert("xn--mgbt3dhd", "whois.nic.xn--mgbt3dhd");
    m.insert("xn--mgbtx2b", "whois.cmc.iq");
    m.insert("xn--mgbx4cd0ab", "whois.mynic.my");
    m.insert("xn--mix891f", "whois.monic.mo");
    m.insert("xn--mk1bu44c", "whois.nic.xn--mk1bu44c");
    m.insert("xn--mxtq1m", "whois.nic.xn--mxtq1m");
    m.insert("xn--ngbc5azd", "whois.nic.xn--ngbc5azd");
    m.insert("xn--ngbe9e0a", "whois.nic.xn--ngbe9e0a");
    m.insert("xn--ngbrx", "whois.nic.xn--ngbrx");
    m.insert("xn--nqv7f", "whois.nic.xn--nqv7f");
    m.insert("xn--nqv7fs00ema", "whois.nic.xn--nqv7fs00ema");
    m.insert("xn--o3cw4h", "whois.thnic.co.th");
    m.insert("xn--ogbpf8fl", "whois.tld.sy");
    m.insert("xn--p1ai", "whois.tcinet.ru");
    m.insert("xn--pgbs0dh", "whois.ati.tn");
    m.insert("xn--pssy2u", "whois.nic.xn--pssy2u");
    m.insert("xn--q7ce6a", "whois.nic.la");
    m.insert("xn--qxa6a", "whois.eu");
    m.insert("xn--rovu88b", "whois.nic.xn--rovu88b");
    m.insert("xn--rvc1e0am3e", "whois.nixiregistry.in");
    m.insert("xn--s9brj9c", "whois.nixiregistry.in");
    m.insert("xn--ses554g", "whois.nic.xn--ses554g");
    m.insert("xn--t60b56a", "whois.nic.xn--t60b56a");
    m.insert("xn--tckwe", "whois.nic.xn--tckwe");
    m.insert("xn--tiq49xqyj", "whois.nic.xn--tiq49xqyj");
    m.insert("xn--unup4y", "whois.nic.xn--unup4y");
    m.insert(
        "xn--vermgensberater-ctb",
        "whois.nic.xn--vermgensberater-ctb",
    );
    m.insert(
        "xn--vermgensberatung-pwb",
        "whois.nic.xn--vermgensberatung-pwb",
    );
    m.insert("xn--vhquv", "whois.nic.xn--vhquv");
    m.insert("xn--vuq861b", "whois.teleinfo.cn");
    m.insert("xn--w4r85el8fhu5dnra", "whois.nic.xn--w4r85el8fhu5dnra");
    m.insert("xn--w4rs40l", "whois.nic.xn--w4rs40l");
    m.insert("xn--wgbh1c", "whois.dotmasr.eg");
    m.insert("xn--wgbl6a", "whois.registry.qa");
    m.insert("xn--xhq521b", "whois.ngtld.cn");
    m.insert("xn--xkc2al3hye2a", "whois.nic.lk");
    m.insert("xn--xkc2dl3a5ee0h", "whois.nixiregistry.in");
    m.insert("xn--y9a3aq", "whois.amnic.net");
    m.insert("xn--yfro4i67o", "whois.zh.sgnic.sg");
    m.insert("xn--ygbi2ammx", "whois.pnina.ps");
    m.insert("xn--zfr164b", "whois.conac.cn");

    // ============================================================
    // Internationalized TLDs — Unicode aliases
    // ============================================================
    m.insert("vermögensberater", "whois.nic.xn--vermgensberater-ctb");
    m.insert("vermögensberatung", "whois.nic.xn--vermgensberatung-pwb");
    m.insert("ευ", "whois.eu");
    m.insert("бг", "whois.imena.bg");
    m.insert("бел", "whois.cctld.by");
    m.insert("дети", "whois.nic.xn--d1acj3b");
    m.insert("ею", "whois.eu");
    m.insert("католик", "whois.nic.xn--80aqecdr1a");
    m.insert("ком", "whois.nic.xn--j1aef");
    m.insert("мкд", "whois.marnet.mk");
    m.insert("мон", "whois.mn");
    m.insert("москва", "whois.nic.xn--80adxhks");
    m.insert("онлайн", "whois.nic.xn--80asehdb");
    m.insert("орг", "whois.nic.xn--c1avg");
    m.insert("рф", "whois.tcinet.ru");
    m.insert("сайт", "whois.nic.xn--80aswg");
    m.insert("срб", "whois.rnids.rs");
    m.insert("укр", "whois.dotukr.com");
    m.insert("қаз", "whois.nic.kz");
    m.insert("հայ", "whois.amnic.net");
    m.insert("ישראל", "whois.isoc.org.il");
    m.insert("קום", "whois.nic.xn--9dbq2a");
    m.insert("ابوظبي", "whois.nic.xn--mgbca7dzdo");
    m.insert("الجزائر", "whois.nic.dz");
    m.insert("السعودية", "whois.nic.net.sa");
    m.insert("العليان", "whois.nic.xn--mgba7c0bbn0a");
    m.insert("امارات", "whois.aeda.net.ae");
    m.insert("ایران", "whois.nic.ir");
    m.insert("بارت", "whois.nixiregistry.in");
    m.insert("بازار", "whois.nic.xn--mgbab2bd");
    m.insert("بيتك", "whois.nic.xn--ngbe9e0a");
    m.insert("بھارت", "whois.nixiregistry.in");
    m.insert("تونس", "whois.ati.tn");
    m.insert("سورية", "whois.tld.sy");
    m.insert("شبكة", "whois.nic.xn--ngbc5azd");
    m.insert("عراق", "whois.cmc.iq");
    m.insert("عرب", "whois.nic.xn--ngbrx");
    m.insert("عمان", "whois.registry.om");
    m.insert("فلسطين", "whois.pnina.ps");
    m.insert("قطر", "whois.registry.qa");
    m.insert("كاثوليك", "whois.nic.xn--mgbi4ecexp");
    m.insert("كوم", "whois.nic.xn--fhbei");
    m.insert("مصر", "whois.dotmasr.eg");
    m.insert("مليسيا", "whois.mynic.my");
    m.insert("موريتانيا", "whois.nic.mr");
    m.insert("موقع", "whois.nic.xn--4gbrim");
    m.insert("همراه", "whois.nic.xn--mgbt3dhd");
    m.insert("ڀارت", "whois.nixiregistry.in");
    m.insert("कॉम", "whois.nic.xn--11b4c3d");
    m.insert("नेट", "whois.nic.xn--c2br7g");
    m.insert("भारत", "whois.nixiregistry.in");
    m.insert("भारतम्", "whois.nixiregistry.in");
    m.insert("भारोत", "whois.nixiregistry.in");
    m.insert("संगठन", "whois.nic.xn--i1b6b1a6a2e");
    m.insert("ভারত", "whois.nixiregistry.in");
    m.insert("ভাৰত", "whois.nixiregistry.in");
    m.insert("ਭਾਰਤ", "whois.nixiregistry.in");
    m.insert("ભારત", "whois.nixiregistry.in");
    m.insert("ଭାରତ", "whois.nixiregistry.in");
    m.insert("இந்தியா", "whois.nixiregistry.in");
    m.insert("இலங்கை", "whois.nic.lk");
    m.insert("சிங்கப்பூர்", "whois.ta.sgnic.sg");
    m.insert("భారత్", "whois.nixiregistry.in");
    m.insert("ಭಾರತ", "whois.nixiregistry.in");
    m.insert("ഭാരതം", "whois.nixiregistry.in");
    m.insert("ලංකා", "whois.nic.lk");
    m.insert("คอม", "whois.nic.xn--42c2d9a");
    m.insert("ไทย", "whois.thnic.co.th");
    m.insert("ລາວ", "whois.nic.la");
    m.insert("アマゾン", "whois.nic.xn--cckwcxetd");
    m.insert("クラウド", "whois.nic.xn--gckr3f0f");
    m.insert("コム", "whois.nic.xn--tckwe");
    m.insert("ストア", "whois.nic.xn--cck2b3b");
    m.insert("セール", "whois.nic.xn--1ck2e1b");
    m.insert("ファッション", "whois.nic.xn--bck1b9a5dre4c");
    m.insert("ポイント", "whois.nic.xn--eckvdtc9d");
    m.insert("中信", "whois.gtld.zdns.cn");
    m.insert("中国", "whois.cnnic.cn");
    m.insert("中國", "whois.cnnic.cn");
    m.insert("中文网", "whois.teleinfo.cn");
    m.insert("亚马逊", "whois.nic.xn--jlq480n2rg");
    m.insert("企业", "whois.nic.xn--vhquv");
    m.insert("佛山", "whois.ngtld.cn");
    m.insert("信息", "whois.teleinfo.cn");
    m.insert("八卦", "whois.gtld.zdns.cn");
    m.insert("公司", "whois.ngtld.cn");
    m.insert("公益", "whois.conac.cn");
    m.insert("台湾", "whois.twnic.net.tw");
    m.insert("台灣", "whois.twnic.net.tw");
    m.insert("商城", "whois.gtld.zdns.cn");
    m.insert("商店", "whois.nic.xn--czrs0t");
    m.insert("嘉里", "whois.nic.xn--w4rs40l");
    m.insert("嘉里大酒店", "whois.nic.xn--w4r85el8fhu5dnra");
    m.insert("在线", "whois.teleinfo.cn");
    m.insert("大拿", "whois.nic.xn--pssy2u");
    m.insert("天主教", "whois.nic.xn--tiq49xqyj");
    m.insert("娱乐", "whois.nic.xn--fjq720a");
    m.insert("家電", "whois.nic.xn--fct429k");
    m.insert("广东", "whois.ngtld.cn");
    m.insert("微博", "whois.nic.xn--9krt00a");
    m.insert("慈善", "whois.gtld.zdns.cn");
    m.insert("我爱你", "whois.gtld.zdns.cn");
    m.insert("手机", "whois.nic.xn--kput3i");
    m.insert("政务", "whois.conac.cn");
    m.insert("政府", "whois.nic.xn--mxtq1m");
    m.insert("新加坡", "whois.zh.sgnic.sg");
    m.insert("新闻", "whois.gtld.zdns.cn");
    m.insert("时尚", "whois.gtld.zdns.cn");
    m.insert("書籍", "whois.nic.xn--rovu88b");
    m.insert("机构", "whois.nic.xn--nqv7f");
    m.insert("淡马锡", "whois.nic.xn--b4w605ferd");
    m.insert("游戏", "whois.nic.xn--unup4y");
    m.insert("澳門", "whois.monic.mo");
    m.insert("点看", "whois.nic.xn--3pxu8k");
    m.insert("移动", "whois.nic.xn--6frz82g");
    m.insert("组织机构", "whois.nic.xn--nqv7fs00ema");
    m.insert("网址", "whois.nic.xn--ses554g");
    m.insert("网店", "whois.gtld.zdns.cn");
    m.insert("网站", "whois.nic.xn--5tzm5g");
    m.insert("网络", "whois.ngtld.cn");
    m.insert("联通", "whois.nic.xn--8y0a063a");
    m.insert("购物", "whois.nic.xn--g2xx48c");
    m.insert("通販", "whois.nic.xn--gk3at1e");
    m.insert("集团", "whois.gtld.zdns.cn");
    m.insert("電訊盈科", "whois.nic.xn--fzys8d69uvgm");
    m.insert("飞利浦", "whois.nic.xn--kcrx77d1x4a");
    m.insert("食品", "whois.nic.xn--jvr189m");
    m.insert("香格里拉", "whois.nic.xn--5su34j936bgsg");
    m.insert("香港", "whois.hkirc.hk");
    m.insert("닷넷", "whois.nic.xn--t60b56a");
    m.insert("닷컴", "whois.nic.xn--mk1bu44c");
    m.insert("삼성", "whois.kr");
    m.insert("한국", "whois.kr");

    m
});

pub fn get_whois_server(tld: &str) -> Option<&'static str> {
    WHOIS_SERVERS.get(tld.to_lowercase().as_str()).copied()
}

pub fn get_tld(domain: &str) -> Option<&str> {
    domain.rsplit('.').next()
}

/// Returns a suggested registry website URL for a TLD.
/// Derives the URL from the WHOIS server hostname when possible.
pub fn get_registry_url(tld: &str) -> Option<String> {
    let tld_lower = tld.to_lowercase();

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
pub const RDAP_ONLY_TLDS: &[&str] = &[
    "ads", "android", "app", "boo", "cal", "channel", "chrome", "dad", "day", "dev", "docs",
    "drive", "eat", "esq", "fly", "foo", "gle", "gmail", "goog", "google", "hangout", "here",
    "how", "ing", "meet", "meme", "mov", "new", "nexus", "page", "phd", "play", "prof", "rsvp",
    "search", "soy", "youtube", "zip",
];

/// Returns every TLD seer knows about: the WHOIS server map keys unioned with
/// the RDAP-only TLDs, sorted and deduplicated. Backs the TUI TLD browser so it
/// can list the full ~1,400-entry catalog instead of a hardcoded handful.
pub fn all_tlds() -> &'static [&'static str] {
    static ALL: Lazy<Vec<&'static str>> = Lazy::new(|| {
        let mut v: Vec<&'static str> = WHOIS_SERVERS.keys().copied().collect();
        v.extend_from_slice(RDAP_ONLY_TLDS);
        v.sort_unstable();
        v.dedup();
        v
    });
    &ALL
}

#[cfg(test)]
mod all_tlds_tests {
    use super::*;

    #[test]
    fn all_tlds_is_sorted_deduped_and_large() {
        let tlds = all_tlds();
        assert!(
            tlds.len() > 1000,
            "expected the full catalog, got {}",
            tlds.len()
        );
        // Sorted + deduplicated.
        for w in tlds.windows(2) {
            assert!(w[0] < w[1], "not strictly sorted at {:?}", w);
        }
    }

    #[test]
    fn all_tlds_includes_whois_and_rdap_only() {
        let tlds = all_tlds();
        // A WHOIS-mapped TLD and an RDAP-only one both appear.
        assert!(tlds.contains(&"com"), "com (WHOIS) should be present");
        assert!(tlds.contains(&"app"), "app (RDAP-only) should be present");
        assert!(tlds.contains(&"dev"), "dev (RDAP-only) should be present");
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
        ] {
            assert!(
                get_whois_server(tld).is_none(),
                ".{tld} must not be mapped (IANA-delisted, dead hostname)"
            );
        }
    }
}
