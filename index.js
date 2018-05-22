"use strict";

const Discord = require(`discord.js`),
    Client = new Discord.Client(),
    Config = require(`./config/private.json`),
    Developers = [`379918962668077060`],
    Prefix = `-`,
    Request = require(`request`),
    StatusMessage = [`WINNER WINNER CHICKEN DINNER!`, `大吉大利，晚上吃鸡!`, `이겼닭! 오늘 저녁은 치킨이닭!`, `GEWINNER GEWINNER HUHNCHEN-DINNER!`, `MECZYK WYGRANY, KURCZAK PODANY!`, `Grande Vitória!`, `ПОБЕДА-ПОБЕДА ВМЕСТО ОБЕДА!`, `HADİ İYİSİN! ÇORBA PARASI ÇIKTI 🙂`, `ฉนะ!กินฉลองกัน!`, `勝った！勝った！夕飯はドン勝だ！！`],
    DataBases = {
        "website": {
            "shorturl": require(`./database/website/shorturl.json`)
        }
    },
    Language = {
        "ja_jp": {
            "changelog": require(`./ja_jp/changelog.json`),
            "level": `high`,
            "main": require(`./ja_jp/main.json`)
        }
    },
    Message = {
        send: (Message, Content) => {

            if (Message && Content) {

                return Message.channel.send(Content);

            } else if (!Message) {

                Problem.Record(`Message.send`, Problem.Missing, `Message`, CallStack(3));
                return false;

            }

        }
    },
    Problem = {
        Invalid: `Invalid`,
        Match: `Match`,
        Missing: `Missing`,
        Record: (Name, Type, Content, Stack) => {

            if (Type === `Missing`) {

                console.error(`\u001b[31m${g(`log.error`)} ${g(`error.missing`, Name, Content, Stack)}`);

            } else if (Type === `Invalid`) {

                console.error(`\u001b[31m${g(`log.error`)} ${g(`error.invalid`, Name, Content, Stack)}`);

            } else if (Type === `Match`) {

                console.error(`\u001b[31m${g(`log.error`)} ${g(`error.match`, Name, Content, Stack)}`);

            } else {

                console.error(`\u001b[31m${g(`log.error`)} ${g(`error.invalid`, `Problem.Record`, `Type`, CallStack(2))}`);

            }

        }
    },
    Rexp = {
        URL: /(https?:\/\/[^\s]+)/g
    },
    is = {
        Developer: (Message) => {

            if (Developers.includes(Message.author.id)) {

                return true;

            }
            return false;

        }
    },
    CallStack = (line) => {

        try {

            throw new Error(`Dummy`);

        } catch (c) {

            return c.stack.split(`\n`)[line].split(`(`)[1].replace(`)`, ``);

        }

    },
    DetectURL = (c) => c.match(Rexp.URL),
    Lower = (string) => string.toLowerCase(),
    g = (Code, AttData, AttData2, AttData3, AttData4, AttData5) => Language.ja_jp.main[Code].replace(`%s%1;`, AttData).replace(`%s%2;`, AttData2).replace(`%s%3;`, AttData3).replace(`%s%4;`, AttData4).replace(`%s%5;`, AttData5);

let Disconnected = false,
    Launched = false,
    Status = 0,
    TestMode = false;
Client.on(`ready`, () => {

    if (Disconnected) {

        console.log(`${g(`log.bot`)} ${g(`log.red`)}`);

    }
    Client.user.setActivity(`勝った！勝った！夕飯はドン勝だ！！`, {
        type: `STREAMING`
    });
    console.log(`${g(`log.bot`)} ${g(`log.waiting`)}`);
    setTimeout(() => {

        Launched = true;
        console.log(`---${g(`log.logg`)}---\n${g(`log.discord`) + Config.Discord.slice(0, 20) + `*`.repeat(Config.Discord.length - 20)}\n${g(`log.tag`) + Client.user.tag}\n${g(`log.id`) + Client.user.id}\n${g(`log.ping`) + Math.floor(Client.ping)}ms\n---${g(`log.logg`)}---\n`);

    }, 1000);
    setInterval(() => {

        Status = StatusMessage[Math.floor(Math.random() * StatusMessage.length)];
        Client.user.setActivity(Status, {
            type: `STREAMING`
        });
        console.log(`${g(`log.bot`)} ${g(`log.updsts`) + Status}`);

    }, 30000);

}).on(`message`, (m) => {

    if (!Launched) return;
    if (m.author.id === Client.user.id) return;
    console.log(`${g(`log.log`)} ${g(`log.say`, m.author.tag, m.guild.name, m.channel.name, m.content)}`);
    if (m.channel.type === `dm`) return;
    if (TestMode && !is.Developer(m)) return;
    if (m.author.bot) return;
    const s = m.content.slice(Prefix.length).split(` `);
    new Promise((resolve) => {

        if (s[0] !== `scan` && DetectURL(m.content)) {

            Request({
                headers: {
                    "Content-Type": `application/json`,
                    "User-Agent": `Nulling`
                },
                json: true,
                method: `POST`,
                qs: {
                    apikey: Config.VirusTotal,
                    resource: DetectURL(m.content)[0]
                },
                url: `https://www.virustotal.com/vtapi/v2/url/report`
            }, (e, r, b) => {

                if (b.positives > 0 && b.response_code !== 0) {

                    m.delete(0);
                    m.channel.send(g(`scan.mal`, m.author)).then((msg) => msg.delete(3000));
                    resolve(false);

                } else {

                    resolve(true);

                }

            });

        } else {

            resolve(true);

        }

    }).then((r) => {

        if (r) {

            if (m.content.startsWith(Prefix)) {

                const s = m.content.slice(Prefix.length).split(` `);
                m.react(`👌`);
                if (s[0] === `ping`) {

                    Message.send(m, g(`command.ping.success`, Math.floor(Client.ping), Date.now() - m.createdTimestamp));

                } else if (s[0] === `help`) {

                    if (s[1] === `help`) {

                        m.channel.send(new Discord.RichEmbed().setTitle(`help`).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(g(`command.help.help.desc`)).addField(g(`command.help.sub`), `\`help **[${g(`command.help.help.sub.name.name`)}]**\`: ${g(`command.help.help.sub.name.desc`)} (${g(`command.help.optional`)})`).setColor(`#7289da`));

                    } else if (s[1] === `ping`) {

                        m.channel.send(new Discord.RichEmbed().setTitle(`ping`).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(g(`command.help.ping.desc`)).addField(g(`command.help.sub`), g(`command.help.none`)).setColor(`#7289da`));

                    } else if (s[1] === `qrcode`) {

                        m.channel.send(new Discord.RichEmbed().setTitle(`qrcode`).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(g(`command.help.qrcode.desc`)).addField(g(`command.help.sub`), `\`qrcode **[${g(`command.help.qrcode.sub.encode.name`)}]**\`: ${g(`command.help.qrcode.sub.encode.desc`)} (${g(`command.help.nonoptional`)})\n\`qrcode [${`command.help.qrcode.sub.encode.name`}] **[${g(`command.help.qrcode.sub.text.name`)}]**\`: ${g(`command.help.qrcode.sub.text.desc`)} (${g(`command.help.nonoptional`)})`).addField(g(`command.help.encode`), `\`UTF-8\` \`Shift_JIS\` \`ISO-8859-1\``).setColor(`#7289da`));

                    } else if (s[1] === undefined) {

                        m.channel.send(new Discord.RichEmbed().setTitle(g(`command.help.title`)).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(g(`command.help.tip`)).addField(g(`command.help.category.bot`), `\`help\` \`ping\` \`invite\``, true).addField(g(`command.help.category.util`), `\`qrcode\``, true).addField(g(`command.help.category.security`), `\`scan\``, true).addField(g(`command.help.category.shorturl`), `\`bitly\``, true).addField(g(`command.help.category.develop`), `\`eval\` \`testmode\``, true).setColor(`#7289da`));

                    }

                } else if (s[0] === `qrcode`) {

                    if (s[1]) {

                        if (s[1] === `UTF-8` || s[1] === `Shift_JIS` || s[1] === `ISO-8859-1`) {

                            if (m.content.slice(s[0].length + s[1].length + 3)) {

                                m.channel.send(new Discord.RichEmbed().setTitle(g(`command.qrcode.success`)).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(`${g(`command.qrcode.imagelink`)}https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${m.content.slice(s[0].length + s[1].length + 3)}&choe=${s[1]}&chld=H|1`).setImage(`https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${m.content.slice(s[0].length + s[1].length + 3)}&choe=${s[1]}&chld=H|1`).setColor(`#7289da`));

                            } else {

                                Message.send(m, g(`error.msg.7`));

                            }

                        } else {

                            Message.send(m, g(`error.msg.6`));

                        }

                    } else {

                        Message.send(m, g(`error.msg.5`));

                    }

                } else if (s[0] === `invite`) {

                    Message.send(m, `\`\`\`\n${g(`command.invite.bot`)}\n\`\`\`https://discordapp.com/oauth2/authorize?client_id=415808907903107072&permissions=8&redirect_uri=https%3A%2F%2Fnull-coding.github.io%2Fthank-you%2Findex.html&response_type=code&scope=bot%20identify\n\`\`\`${g(`command.invite.note`)} \n\`\`\`\n\`\`\`${g(`command.invite.group`)}\`\`\`https://discord.gg/6DuyES3`);

                } else if (s[0] === `bitly`) {

                    if (m.content.slice(s[0].length + 2)) {

                        if (m.content.slice(s[0].length + 2).length <= 14) {

                            Message.send(m, g(`error.msg.3`), m.content.slice(s[0].length + 2));

                        } else {

                            new Promise((resolve) => {

                                for (let i = 0; i < DataBases.website.shorturl.main.length; i++) {

                                    if (Lower(m.content.slice(s[0].length + 2)).indexOf(DataBases.website.shorturl.main[i]) !== -1) {

                                        Message.send(m, g(`command.bitly.error.4`));
                                        return;

                                    }

                                }
                                resolve();

                            }).then(() => {

                                Request({
                                    headers: {
                                        "Content-Type": `application/json`,
                                        "User-Agent": `Nulling`
                                    },
                                    json: true,
                                    method: `POST`,
                                    qs: {
                                        access_token: Config.Bitly,
                                        longUrl: `https://${m.content.slice(s[0].length + 2)}`
                                    },
                                    url: `https://api-ssl.bitly.com/v3/shorten`
                                }, (e, r, b) => {

                                    if (b.status_code === 500) {

                                        if (b.status_txt === `INVALID_ARG_ACCESS_TOKEN`) {

                                            Problem.Record(`Request - Bitly`, Problem.Invalid, g(`log.acc`), CallStack());
                                            Message.send(m, g(`error.msg.zero`), `${g(`error.code`) + b.status_code}\n${g(`error.content`) + b.status_txt}\n${g(`error.result`) + b.data}\nJSON${g(`error.json`) + JSON.stringify(b)}`);
                                            console.log(`${g(`log.error`)} ${b}`);

                                        }
                                        if (b.status_txt === `INVALID_URI`) {

                                            Message.send(m, g(`error.msg.2`, m.content.slice(s[0].length + 2)));

                                        }

                                    } else if (b.status_code === 200) {

                                        if (b.status_txt === `OK`) {

                                            Message.send(m, g(`command.bitly.success`, m.content.slice(s[0].length + 2), `https://bit.ly/${b.data.hash}`));

                                        } else {

                                            Problem.Record(`Request - Bitly`, Problem.Invalid, g(`log.rmsg`), CallStack());

                                        }

                                    } else {

                                        Problem.Record(`Request - Bitly`, Problem.Invalid, g(`log.rcode`), CallStack());

                                    }

                                });

                            });

                        }

                    } else {

                        Message.send(m, g(`error.msg.1`));

                    }

                } else if (s[0] === `scan`) {

                    m.delete(0);
                    if (m.content.slice(s[0].length + 2)) {

                        Request({
                            body: {
                                "client": {
                                    "clientId": `Nulling`,
                                    "clientVersion": `0.0.1`
                                },
                                "threatInfo": {
                                    "platformTypes": [`ALL_PLATFORMS`],
                                    "threatEntries": [{
                                        "url": m.content.slice(s[0].length + 2)
                                    }],
                                    "threatEntryTypes": [`URL`],
                                    "threatTypes": [`MALWARE`, `SOCIAL_ENGINEERING`]
                                }
                            },
                            headers: {
                                "Content-Type": `application/json`,
                                "User-Agent": `Nulling`
                            },
                            json: true,
                            method: `POST`,
                            qs: {
                                key: Config.Google
                            },
                            url: `https://safebrowsing.googleapis.com/v4/threatMatches:find`
                        }, (e, r, body) => {

                            Request({
                                headers: {
                                    "Content-Type": `application/json`,
                                    "User-Agent": `Nulling`
                                },
                                json: true,
                                method: `POST`,
                                qs: {
                                    apikey: Config.VirusTotal,
                                    resource: m.content.slice(s[0].length + 2)
                                },
                                url: `https://www.virustotal.com/vtapi/v2/url/report`
                            }, (e, r, b) => {

                                Message.send(m, g(`command.scan.success`, m.author));
                                if (b.response_code !== 0) {

                                    m.author.send(new Discord.RichEmbed().setTitle(g(`command.scan.result`)).setAuthor(`@${m.author.tag}`, m.author.avatarURL).setDescription(`${g(`command.scan.url`) + m.content.slice(s[0].length + 2)}\n${g(`command.scan.engr`, b.positives)}\n${g(`command.scan.tip`)}`).addField(`Google`, body.matches === undefined ? g(`command.scan.n`) : body.matches[0].threatType === `MALWARE` ? g(`command.scan.m`) : body.matches[0].threatType === `SOCIAL_ENGINEERING` ? g(`command.scan.p`) : g(`command.scan.u`), true).addField(`Kaspersky`, b.scans.Kaspersky.result === `malicious site` || b.scans.Kaspersky.result === `malware site` ? g(`command.scan.m`) : b.scans.Kaspersky.result === `phishing site` ? g(`command.scan.p`) : b.scans.Kaspersky.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`BitDefender`, b.scans.BitDefender.result === `malicious site` || b.scans.BitDefender.result === `malware site` ? g(`command.scan.m`) : b.scans.BitDefender.result === `phishing site` ? g(`command.scan.p`) : b.scans.BitDefender.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Avira`, b.scans.Avira.result === `malicious site` || b.scans.Avira.result === `malware site` ? g(`command.scan.m`) : b.scans.Avira.result === `phishing site` ? g(`command.scan.p`) : b.scans.Avira.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Fortinet`, b.scans.Fortinet.result === `malicious site` || b.scans.Fortinet.result === `malicious site` === `malware site` ? g(`command.scan.m`) : b.scans.Fortinet.result === `phishing site` ? g(`command.scan.p`) : b.scans.Fortinet.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Yandex`, b.scans[`Yandex Safebrowsing`].result === `malicious site` || b.scans[`Yandex Safebrowsing`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Yandex Safebrowsing`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Yandex Safebrowsing`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Sophos`, b.scans.Sophos.result === `malicious site` || b.scans.Sophos.result === `malware site` ? g(`command.scan.m`) : b.scans.Sophos.result === `phishing site` ? g(`command.scan.p`) : b.scans.Sophos.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`ESET`, b.scans.ESET.result === `malicious site` || b.scans.ESET.result === `malware site` ? g(`command.scan.m`) : b.scans.ESET.result === `phishing site` ? g(`command.scan.p`) : b.scans.ESET.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Dr.Web`, b.scans[`Dr.Web`].result === `malicious site` || b.scans[`Dr.Web`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Dr.Web`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Dr.Web`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Google${g(`command.scan.old`)}`, b.scans[`Google Safebrowsing`].result === `malicious site` || b.scans[`Google Safebrowsing`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Google Safebrowsing`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Google Safebrowsing`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`AutoShun`, b.scans.AutoShun.result === `malicious site` || b.scans.AutoShun.result === `malware site` ? g(`command.scan.m`) : b.scans.AutoShun.result === `phishing site` ? g(`command.scan.p`) : b.scans.AutoShun.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`CyRadar`, b.scans.CyRadar.result === `malicious site` || b.scans.CyRadar.result === `malware site` ? g(`command.scan.m`) : b.scans.CyRadar.result === `phishing site` ? g(`command.scan.p`) : b.scans.CyRadar.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Forcepoint ThreatSeeker`, b.scans[`Forcepoint ThreatSeeker`].result === `malicious site` || b.scans[`Forcepoint ThreatSeeker`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Forcepoint ThreatSeeker`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Forcepoint ThreatSeeker`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Malware Domain Blocklist`, b.scans[`Malware Domain Blocklist`].result === `malicious site` || b.scans[`Malware Domain Blocklist`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Malware Domain Blocklist`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Malware Domain Blocklist`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Rising`, b.scans.Rising.result === `malicious site` || b.scans.Rising.result === `malware site` ? g(`command.scan.m`) : b.scans.Rising.result === `phishing site` ? g(`command.scan.p`) : b.scans.Rising.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Spam404`, b.scans.Spam404.result === `malicious site` || b.scans.Spam404.result === `malware site` ? g(`command.scan.m`) : b.scans.Spam404.result === `phishing site` ? g(`command.scan.p`) : b.scans.Spam404.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Dr.Web`, b.scans[`Dr.Web`].result === `malicious site` || b.scans[`Dr.Web`].result === `malware site` ? g(`command.scan.m`) : b.scans[`Dr.Web`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Dr.Web`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`MalwareDomainList`, b.scans.MalwareDomainList.result === `malicious site` || b.scans.MalwareDomainList.result === `malware site` ? g(`command.scan.m`) : b.scans.MalwareDomainList.result === `phishing site` ? g(`command.scan.p`) : b.scans.MalwareDomainList.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`G-Data`, b.scans[`G-Data`].result === `malicious site` || b.scans[`G-Data`].result === `malware site` ? g(`command.scan.m`) : b.scans[`G-Data`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`G-Data`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Malc0de Database`, b.scans[`Malc0de Database`].result === `malicious site` || b.scans[`Malc0de Database`] === `malware site` ? g(`command.scan.m`) : b.scans[`Malc0de Database`].result === `phishing site` ? g(`command.scan.p`) : b.scans[`Malc0de Database`].result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`DNS8`, b.scans.DNS8.result === `malicious site` || b.scans.DNS8.result === `malware site` ? g(`command.scan.m`) : b.scans.DNS8.result === `phishing site` ? g(`command.scan.p`) : b.scans.DNS8.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Quttera`, b.scans.Quttera.result === `malicious site` || b.scans.Quttera.result === `malware site` ? g(`command.scan.m`) : b.scans.Quttera.result === `phishing site` ? g(`command.scan.p`) : b.scans.Quttera.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Phishtank`, b.scans.Phishtank.result === `malicious site` || b.scans.Phishtank.result === `malware site` ? g(`command.scan.m`) : b.scans.Phishtank.result === `phishing site` ? g(`command.scan.p`) : b.scans.Phishtank.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Trustwave`, b.scans.Trustwave.result === `malicious site` || b.scans.Trustwave.result === `malware site` ? g(`command.scan.m`) : b.scans.Trustwave.result === `phishing site` ? g(`command.scan.p`) : b.scans.Trustwave.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).addField(`Emsisoft`, b.scans.Emsisoft.result === `malicious site` || b.scans.Emsisoft.result === `malware site` ? g(`command.scan.m`) : b.scans.Emsisoft.result === `phishing site` ? g(`command.scan.p`) : b.scans.Emsisoft.result === `suspicious site` ? g(`command.scan.s`) : g(`command.scan.n`), true).setFooter(`Powered By VirusTotal and Google Safebrowsing | https://virustotal.com https://safebrowsing.google.com`).setColor(`#7289da`));

                                } else {

                                    m.author.send(new Discord.RichEmbed().setTitle(g(`command.scan.result`)).setDescription(`URL: ${m.content.slice(s[0].length + 2)}\n${g(`error.msg.8`)}`).setAuthor(`@${m.author.tag}`, m.author.avatarURL).addField(`Google Safebrowsing`, body.matches === undefined ? g(`command.scan.n`) : body.matches[0].threatType === `MALWARE` ? g(`command.scan.m`) : body.matches[0].threatType === `SOCIAL_ENGINEERING` ? g(`command.scan.p`) : `不明`, true).setFooter(`Powered By Google Safebrowsing | https://safebrowsing.google.com`, `https://developers.google.com/safe-browsing/images/SafeBrowsing_Icon.png`).setColor(`#7289da`));

                                }

                            });

                        });

                    } else {

                        Message.send(m, g(`error.msg.9`));

                    }

                } else if (s[0] === `eval`) {

                    if (is.Developer(m)) {

                        if (m.content.slice(s[0].length + 2)) {

                            try {

                                eval(m.content.slice(s[0].length + 2));

                            } catch (e) {

                                Message.send(m, g(`error.msg.12`, m.author));
                                m.author.send(`${g(`command.eval.stacktrace`)}\n${e.stack}`);

                            }

                        } else {

                            Message.send(m, g(`error.msg.10`));

                        }

                    } else {

                        Message.send(m, g(`error.msg.11`));

                    }

                } else if (s[0] === `guild`) {

                    m.channel.send(
                        new Discord.RichEmbed()
                            .setTitle(g(`command.guild.title`, m.guild.name))
                            .setDescription(g(`command.guild.tip`))
                            .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                            .setThumbnail(m.guild.iconURL)
                            .addField(g(`command.guild.name`), m.guild.name, true)
                            .addField(g(`command.guild.nameAcronym`), m.guild.nameAcronym, true)
                            .addField(g(`command.guild.id`), m.guild.id, true)
                            .addField(g(`command.guild.region`), m.guild.region === `brazil` ? g(`region.brazil`) : m.guild.region === `eu-central` ? g(`region.centraleu`) : m.guild.region === `hongkong` ? g(`region.hongkong`) : m.guild.region === `japan` ? g(`region.japan`) : m.guild.region === `russia` ? g(`region.russia`) : m.guild.region === `singapore` ? g(`region.singapore`) : m.guild.region === `sydney` ? g(`region.sydney`) : m.guild.region === `us-central` ? g(`region.centralus`) : m.guild.region === `us-east` ? g(`region.eastus`) : m.guild.region === `us-south` ? g(`region.southus`) : m.guild.region === `us-west` ? g(`region.westus`) : m.guild.region === `eu-west` ? g(`region.westeu`) : g(`region.uknown`), true).addField(g(`command.guild.member`), m.guild.memberCount, true)
                            .addField(g(`command.guild.large`), m.guild.large ? g(`command.guild.large.yes`) : !m.guild.large ? g(`command.guild.large.no`) : g(`command.guild.large.unknown`), true)
                            .addField(g(`command.guild.afkTime`), g(`command.guild.afkTime.time`, m.guild.afkTimeout / 60, m.guild.afkTimeout), true)
                            .addField(g(`command.guild.available`), m.guild.available ? g(`command.guild.available.yes`) : !m.guild.available ? g(`command.guild.available.no`) : g(`command.guild.available.unknown`), true)
                            .addField(g(`command.guild.verified`), g(`comingsoon`), true)
                            .addField(g(`command.guild.verif`), m.guild.verificationLevel === 0 ? g(`command.guild.verif.none`) + g(`command.guild.verif.none.desc`) : m.guild.verificationLevel === 1 ? g(`command.guild.verif.low`) + g(`command.guild.verif.low.desc`) : m.guild.verificationLevel === 2 ? g(`command.guild.verif.medium`) + g(`command.guild.verif.medium.desc`) : m.guild.verificationLevel === 3 ? g(`command.guild.verif.high`) + g(`command.guild.verif.high.desc`) : m.guild.verificationLevel === 4 ? g(`command.guild.verif.very_high`) + g(`command.guild.verif.very_high.desc`) : g(`command.guild.verif.unknown`))
                            .addField(g(`command.guild.filter`), m.guild.explicitContentFilter === 0 ? g(`command.guild.filter.none`) + g(`command.guild.filter.none.desc`) : m.guild.explicitContentFilter === 1 ? g(`command.guild.filter.medium`) + g(`command.guild.filter.medium.desc`) : m.guild.explicitContentFilter === 2 ? g(`command.guild.filter.high`) + g(`command.guild.filter.high.desc`) : g(`command.guild.filter.unknown`))
                            .addField(g(`command.guild.afk`), m.guild.afkChannel + g(`command.guild.afk.id`, m.guild.afkChannelID))
                            .addField(g(`command.guild.sysc`), m.guild.systemChannel + g(`command.guild.sysc.id`, m.guild.systemChannelID))
                            .addField(g(`command.guild.owner`), m.guild.owner + g(`command.guild.owner.id`, m.guild.ownerID))
                            .addField(g(`command.guild.created`), m.guild.createdAt)
                            .addField(g(`command.guild.joined`), m.guild.joinedAt)
                            .addField(g(`command.guild.icon`), m.guild.iconURL ? m.guild.iconURL : g(`command.guild.icon.none`))
                            .addField(g(`command.guild.hash`), m.guild.icon ? m.guild.icon : g(`command.guild.hash.none`))
                            .addField(g(`command.guild.splash`), m.guild.splashURL ? m.guild.splashURL : g(`command.guild.splash.none`))
                            .addField(g(`command.guild.hash2`), m.guild.splash ? m.guild.splash : g(`command.guild.hash2.none`)));

                } else if (s[0] === `testmode`) {

                    if (is.Developer(m)) {

                        if (!s[1]) {

                            if (TestMode) {

                                TestMode = false;
                                Message.send(m, g(`command.testmode.off`));

                            } else if (!TestMode) {

                                TestMode = true;
                                Message.send(m, g(`command.testmode.on`));

                            } else {

                                Problem.Record(`if - TestMode`, Problem.Invalid, `TestMode`, CallStack(3));

                            }

                        } else if (s[1] === `on`) {

                            TestMode = true;
                            Message.send(m, g(`command.testmode.one`));

                        } else if (s[1] === `off`) {

                            TestMode = false;
                            Message.send(m, g(`command.testmode.off`));

                        }

                    } else {

                        Message.send(m, g(`error.msg.11`));

                    }

                }

            } else if (m.content.startsWith(`: `)) {

                Message.send(m, g(`reply.compact`));

            } else if (m.content.startsWith(`!disboard bump`)) {

                Message.send(m, g(`reply.disboard`));

            } else if (m.content.startsWith(`!discha-update`)) {

                Message.send(m, `サーバー情報が削除されました。`);

            } else if (m.content.startsWith(`dsl!bump`)) {

                Message.send(m, `Only banned users can bump this server`);

            } else if (m.content.startsWith(`\`\`\``) && m.content.endsWith(`\`\`\``) && is.Developer(m)) {

                m.react(`▶`);

            }

        }

    });

}).on(`messageReactionAdd`, (r, u) => {

    if (!Developers.includes(r.message.author.id)) return;
    if (!Developers.includes(u.id)) return;
    if (u.bot) return;
    if (r.message.content.startsWith(`\`\`\``) && r.message.content.endsWith(`\`\`\``) && r.emoji.name === `▶`) {

        const m = r.message;

        try {

            eval(r.message.content.slice(3, -3));

        } catch (e) {

            Message.send(r.message, g(`error.msg.12`, u));
            u.send(`${g(`command.eval.stacktrace`)}\n${e.stack}`);

        }

    }

}).on(`disconnect`, () => {

    console.log(`${g(`bot.bot`)} ${g(`log.did`)}`);
    Disconnected = true;

}).on(`reconnecting`, () => {

    console.log(`${g(`bot.bot`)} ${g(`log.reg}`)}`);
    Disconnected = true;

});
Client.login(Config.Discord);
