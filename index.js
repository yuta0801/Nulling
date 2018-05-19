"use strict";

const Discord = require(`discord.js`),
    Request = require(`request`),
    Config = require(`./config/private.json`),
    Client = new Discord.Client(),
    Prefix = `-`,

    Language = {
        "ja_jp": {
            "level": `high`,
            "main": require(`./ja_jp/main.json`),
            "changelog": require(`./ja_jp/changelog.json`)
        },
    },

    DataBases = {
        "website": {
            "shorturl": require(`./database/website/shorturl.json`)
        }
    },

    commands = Language.ja_jp.main.commands,
    code_error = Language.ja_jp.main.code_error,

    StatusMessage = [
        `WINNER WINNER CHICKEN DINNER!`,
        `大吉大利，晚上吃鸡!`,
        `이겼닭! 오늘 저녁은 치킨이닭!`,
        `GEWINNER GEWINNER HUHNCHEN-DINNER!`,
        `MECZYK WYGRANY, KURCZAK PODANY!`,
        `Grande Vitória!`,
        `ПОБЕДА-ПОБЕДА ВМЕСТО ОБЕДА!`,
        `HADİ İYİSİN! ÇORBA PARASI ÇIKTI 🙂`,
        `ฉนะ!กินฉลองกัน!`,
        `勝った！勝った！夕飯はドン勝だ！！`
    ],

    Problem = {
        Missing: `Missing`,
        Invalid: `Invalid`,
        Match: `Match`,
        Record: (Function, Type, Content, Stack) => {
            if (Type === `Missing`) {
                console.error(`\u001b[31m関数「${Function}」でエラーが発生しました：引数「${Content}」が足りません\u001b[0m\nエラーの発生源：${Stack}`);
            } else if (Type === `Invalid`) {
                console.error(`\u001b[31m関数「${Function}」でエラーが発生しました：引数「${Content}」が無効です\u001b[0m\nエラーの発生源：${Stack}`);
            } else if (Type === `Invalid`) {
                console.error(`\u001b[31m関数「${Function}」でエラーが発生しました：引数「${Content}」が一致しません\u001b[0m\nエラーの発生源：${Stack}`);
            } else {
                console.error(`\u001b[31m関数 Problem.Record でエラーが発生しました：引数 Type が無効です\u001b[0m\nエラーの発生源：${CallStack()}`);
            }
        }
    },

    Message = {
        Text: `Text`,
        Embed: `Embed`
    },

    Regrex = {
        URL: /(https?:\/\/[^\s]+)/g
    },

    sendMessage = (Message, Type, DataCode, AttData, AttData2, AttData3) => {
        if (Message && Type && DataCode) {
            if (Type === `Text`) {
                Message.channel.send(v(DataCode, AttData, AttData2, AttData3));
            } else if (Type === `Embed`) {
                Message.channel.send(
                    new Discord.RichEmbed()
                        .setAuthor(`@${Message.author.tag}`, Message.author.avatarURL)
                        .setDescription(v(DataCode, AttData, AttData2, AttData3))
                        .setColor(`#7289da`)
                );
            } else {
                Problem.Record(`sendMessage`, Problem.Invalid, `Type`, CallStack());
            }
        } else {
            if (!Message) {
                Problem.Record(`sendMessage`, Problem.Missing, `Message`, CallStack());
            }
            if (!Type) {
                Problem.Record(`sendMessage`, Problem.Missing, `Type`, CallStack());
            }
            if (!DataCode) {
                Problem.Record(`sendMessage`, Problem.Missing, `DataCode`, CallStack());
            }
        }
    },

    v = (DataCode, AttData, AttData2, AttData3) => {
        return DataCode.replace(`%s%1;`, AttData).replace(`%s%2;`, AttData2).replace(`%s%3;`, AttData3);
    },

    CallStack = () => {
        try {
            throw new Error(`Dummy`);
        } catch (content) {
            return content.stack.split(`\n`)[2].split(`(`)[1].replace(`)`, ``);
        }
    },

    ToLower = (string) => {
        return string.toLowerCase();
    },

    DetectURL = (content) => {
        return content.match(Regrex.URL);
    };

let Status = 0,
    Launched = false,
    Disconnected = false,
    TempResult;

Client.on(`ready`, () => {

    if (Disconnected) {
        console.log(`再接続に成功しました`);
    }
    Client.user.setActivity(`WINNER WINNER CHICKEN DINNER!`, { type: `STREAMING` });

    console.log(`ボットが安定するまで待機しています...\n`);

    setTimeout(() => {
        Launched = true;
        console.log(`---ログインが完了しました---\nDiscord のトークン: ${Config.Discord.slice(0, 20)}${`*`.repeat(Config.Discord.length - 20)}\nタグ: ${Client.user.tag}\nID: ${Client.user.id}\nPing: ${Math.floor(Client.ping)}ms\n---ログインが完了しました---\n`);
    }, 1000);

    setInterval(() => {
        Status = StatusMessage[Math.floor(Math.random() * StatusMessage.length)];
        Client.user.setActivity(Status, { type: `STREAMING` });
        console.log(`ステータスメッセージを更新しました: ${Status}`);
    }, 30000);

}).on(`message`, (m) => {

    if (!Launched) return;

    if (m.author.id === Client.user.id) return;

    if (m.author.bot) return;

    console.log(`${m.author.tag} is say "${m.content}" on ${m.guild.name}`);

    const s = m.content.slice(Prefix.length).split(` `);

    new Promise((resolve, reject) => {

        if (s[0] !== `scan` && DetectURL(m.content)) {
            m.channel.send(`${m.author.tag} の送信した URL をスキャンしています。スキャンが終わるまでリンクをクリックしないことをお勧めします。`).then((msg) => {

                Request({
                    url: `https://www.virustotal.com/vtapi/v2/url/report`,
                    method: `POST`,
                    headers: {
                        "Content-Type": `application/json`,
                        "User-Agent": `Nulling`,
                    },
                    json: true,
                    qs: {
                        apikey: Config.VirusTotal,
                        resource: DetectURL(m.content)[0]
                    }
                }, (e, r, b) => {

                    if (b.positives !== 0 && b.response_code !== 0) {

                        m.delete(0);
                        msg.edit(`${m.author.tag} の送信した URL にマルウェアが含まれていたため、削除しました`).then(msg.delete(3000));

                        resolve(false);

                    } else {

                        msg.edit(`${m.author.tag} の送信した URL 「 ${DetectURL(m.content)[0]} 」は安全です`).then(msg.delete(3000));

                        resolve(true);

                    }
                });
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

                    sendMessage(m, Message.Text, commands.ping.success, Math.floor(Client.ping), Date.now() - m.createdTimestamp);

                } else if (s[0] === `help`) {

                    if (s[1] === `help`) {

                        m.channel.send(
                            new Discord.RichEmbed()
                                .setTitle(`help (${commands.help.details.help.name})`)
                                .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                                .setDescription(commands.help.details.help.description)
                                .addField(commands.help.subcommand, `\`help **[${commands.help.details.help.subcommands.cmdname.name}]**\`: ${commands.help.details.help.subcommands.cmdname.description} (${commands.help.optional})`)
                                .setColor(`#7289da`)
                        );

                    } else if (s[1] === `ping`) {

                        m.channel.send(
                            new Discord.RichEmbed()
                                .setTitle(`ping (${commands.help.details.ping.name})`)
                                .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                                .setDescription(commands.help.details.ping.description)
                                .addField(commands.help.subcommand, commands.help.none)
                                .setColor(`#7289da`)
                        );

                    } else if (s[1] === `qrcode`) {

                        m.channel.send(
                            new Discord.RichEmbed()
                                .setTitle(`ping (${commands.help.details.qrcode.name})`)
                                .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                                .setDescription(commands.help.details.qrcode.description)
                                .addField(commands.help.subcommand, `\`qrcode **[${commands.help.details.qrcode.subcommands.charactercode.name}]**\`: ${commands.help.details.qrcode.subcommands.charactercode.description} (${commands.help.nonoptional})\n\`qrcode [${commands.help.details.qrcode.subcommands.charactercode.name}] **[${commands.help.details.qrcode.subcommands.string.name}]**\`: ${commands.help.details.qrcode.subcommands.string.description} (${commands.help.nonoptional})`)
                                .addField(commands.help.charactercodes, `\`UTF-8\` \`Shift_JIS\` \`ISO-8859-1\``)
                                .setColor(`#7289da`)
                        );

                    } else if (s[1] === undefined) {

                        m.channel.send(
                            new Discord.RichEmbed()
                                .setTitle(commands.help.title)
                                .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                                .setDescription(commands.help.tips)
                                .addField(commands.help.categories.bot, `\`help\` \`ping\` \`invite\``, true)
                                .addField(commands.help.categories.utils, `\`qrcode\` \`scan\``, true)
                                .addField(commands.help.categories.shorturl, `\`bitly\``, true)
                                .setColor(`#7289da`)
                        );

                    }

                } else if (s[0] === `qrcode`) {

                    if (s[1]) {

                        if (s[1] === `UTF-8` || s[1] === `Shift_JIS` || s[1] === `ISO-8859-1`) {

                            if (m.content.slice(s[0].length + s[1].length + 3)) {
                                m.channel.send(
                                    new Discord.RichEmbed()
                                        .setTitle(commands.qrcode.success)
                                        .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                                        .setDescription(`${commands.qrcode.imagelink}: https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${m.content.slice(s[0].length + s[1].length + 3)}&choe=${s[1]}&chld=H|1`)
                                        .setImage(`https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${m.content.slice(s[0].length + s[1].length + 3)}&choe=${s[1]}&chld=H|1`)
                                        .setColor(`#7289da`)
                                );

                            } else {
                                sendMessage(m, Message.Text, commands.qrcode.error.three);
                            }

                        } else {
                            sendMessage(m, Message.Text, commands.qrcode.error.two + commands.qrcode.tips);
                        }

                    } else {
                        sendMessage(m, Message.Text, commands.qrcode.error.one + commands.qrcode.tips);
                    }
                } else if (s[0] === `invite`) {
                    sendMessage(m, Message.Text, `\`\`\`\n${commands.invite.bot}\n\`\`\`https://discordapp.com/oauth2/authorize?client_id=415808907903107072&permissions=8&redirect_uri=https%3A%2F%2Fnull-coding.github.io%2Fthank-you%2Findex.html&response_type=code&scope=bot%20identify\n\`\`\`${commands.invite.note} \n\`\`\`\n\`\`\`${commands.invite.group}\`\`\`https://discord.gg/6DuyES3`);
                } else if (s[0] === `bitly`) {
                    if (m.content.slice(s[0].length + 2)) {
                        if (m.content.slice(s[0].length + 2).length <= 14) {
                            sendMessage(m, Message.Text, commands.bitly.error.three, m.content.slice(s[0].length + 2));
                        } else {
                            new Promise((resolve, reject) => {
                                for (let i = 0; i < DataBases.website.shorturl.main.length; i++) {
                                    if (~ToLower(m.content.slice(s[0].length + 2)).indexOf(DataBases.website.shorturl.main[i])) {
                                        sendMessage(m, Message.Text, commands.bitly.error.four);
                                        return;
                                    }
                                }
                                resolve();
                            }).then(() => {
                                Request({
                                    url: `https://api-ssl.bitly.com/v3/shorten`,
                                    method: `POST`,
                                    headers: {
                                        "Content-Type": `application/json`,
                                        "User-Agent": `Nulling`
                                    },
                                    json: true,
                                    qs: {
                                        access_token: Config.Bitly,
                                        longUrl: `https://${m.content.slice(s[0].length + 2)}`
                                    }
                                }, (e, r, b) => {
                                    if (b.status_code === 500) {
                                        if (b.status_txt === `INVALID_ARG_ACCESS_TOKEN`) {
                                            Problem.Record(`Request - Bitly`, Problem.Invalid, `アクセストークン`, CallStack());
                                            sendMessage(m, Message.Text, code_error.message.unknown, `${code_error.code}: ${b.status_code}\n${code_error.content}: ${b.status_txt}\n${code_error.result}: ${b.data}\nJSON${code_error.json}: ${JSON.stringify(b)}`);
                                            console.log(b);
                                        }
                                        if (b.status_txt === `INVALID_URI`) {
                                            sendMessage(m, Message.Text, commands.bitly.error.two, m.content.slice(s[0].length + 2));
                                        }
                                    } else if (b.status_code === 200) {
                                        if (b.status_txt === `OK`) {
                                            sendMessage(m, Message.Text, commands.bitly.success, m.content.slice(s[0].length + 2), `https://bit.ly/${b.data.hash}`);
                                        } else {
                                            Problem.Record(`Request - Bitly`, Problem.Invalid, `応答メッセージ`, CallStack());
                                        }
                                    } else {
                                        Problem.Record(`Request - Bitly`, Problem.Invalid, `応答コード`, CallStack());
                                    }
                                });
                            });
                        }
                    } else {
                        sendMessage(m, Message.Text, commands.bitly.error.one);
                    }
                } else if (s[0] === `scan`) {
                    m.delete(0);
                    if (m.content.slice(s[0].length + 2)) {
                        Request({
                            url: `https://safebrowsing.googleapis.com/v4/threatMatches:find`,
                            method: `POST`,
                            headers: {
                                "Content-Type": `application/json`,
                                "User-Agent": `Nulling`
                            },
                            json: true,
                            qs: {
                                key: Config.Google
                            },
                            body: {
                                "client": {
                                    "clientId": `Nulling`,
                                    "clientVersion": `0.0.1`
                                },
                                "threatInfo": {
                                    "threatTypes": [`MALWARE`, `SOCIAL_ENGINEERING`],
                                    "platformTypes": [`ALL_PLATFORMS`],
                                    "threatEntryTypes": [`URL`],
                                    "threatEntries": [{ "url": m.content.slice(s[0].length + 2) }]
                                }
                            }
                        }, (e, r, body) => {

                            Request({
                                url: `https://www.virustotal.com/vtapi/v2/url/report`,
                                method: `POST`,
                                headers: {
                                    "Content-Type": `application/json`,
                                    "User-Agent": `Nulling`,
                                },
                                json: true,
                                qs: {
                                    apikey: Config.VirusTotal,
                                    resource: m.content.slice(s[0].length + 2)
                                }
                            }, (e, r, b) => {

                                m.channel.send(`<@${m.author.id}> の DM にスキャン結果を送信しました。DM をご確認ください。`);

                                if (b.response_code !== 0) {

                                    m.author.send(
                                        new Discord.RichEmbed()
                                            .setTitle(`スキャン結果`)
                                            .setDescription(`URL: ${m.content.slice(s[0].length + 2)}\n合計 ${b.positives}個のエンジンが脅威を検出しました\n以下は一部のエンジンのスキャン結果です`)
                                            .addField(`Google Safebrowsing`, (body.matches === undefined) ? `未検出` : (body.matches[0].threatType === `MALWARE`) ? `マルウェア` : (body.matches[0].threatType === `SOCIAL_ENGINEERING`) ? `フィッシング` : `不明`, true)
                                            .addField(`Kaspersky`, (b.scans.Kaspersky.result === `malicious site` || b.scans.Kaspersky.result === `malware site`) ? `マルウェア` : (b.scans.Kaspersky.result === `phishing site`) ? `フィッシング` : (b.scans.Kaspersky.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`BitDefender`, (b.scans.BitDefender.result === `malicious site` || b.scans.BitDefender.result === `malware site`) ? `マルウェア` : (b.scans.BitDefender.result === `phishing site`) ? `フィッシング` : (b.scans.BitDefender.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Avira`, (b.scans.Avira.result === `malicious site` || b.scans.Avira.result === `malware site`) ? `マルウェア` : (b.scans.Avira.result === `phishing site`) ? `フィッシング` : (b.scans.Avira.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Fortinet`, (b.scans.Fortinet.result === `malicious site` || b.scans.Fortinet.result === `malicious site` === `malware site`) ? `マルウェア` : (b.scans.Fortinet.result === `phishing site`) ? `フィッシング` : (b.scans.Fortinet.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Yandex Safebrowsing`, (b.scans[`Yandex Safebrowsing`].result === `malicious site` || b.scans[`Yandex Safebrowsing`].result === `malware site`) ? `マルウェア` : (b.scans[`Yandex Safebrowsing`].result === `phishing site`) ? `フィッシング` : (b.scans[`Yandex Safebrowsing`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Sophos`, (b.scans.Sophos.result === `malicious site` || b.scans.Sophos.result === `malware site`) ? `マルウェア` : (b.scans.Sophos.result === `phishing site`) ? `フィッシング` : (b.scans.Sophos.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`ESET`, (b.scans.ESET.result === `malicious site` || b.scans.ESET.result === `malware site`) ? `マルウェア` : (b.scans.ESET.result === `phishing site`) ? `フィッシング` : (b.scans.ESET.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Dr.Web`, (b.scans[`Dr.Web`].result === `malicious site` || b.scans[`Dr.Web`].result === `malware site`) ? `マルウェア` : (b.scans[`Dr.Web`].result === `phishing site`) ? `フィッシング` : (b.scans[`Dr.Web`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Google Safebrowsing (旧)`, (b.scans[`Google Safebrowsing`].result === `malicious site` || b.scans[`Google Safebrowsing`].result === `malware site`) ? `マルウェア` : (b.scans[`Google Safebrowsing`].result === `phishing site`) ? `フィッシング` : (b.scans[`Google Safebrowsing`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`AutoShun`, (b.scans.AutoShun.result === `malicious site` || b.scans.AutoShun.result === `malware site`) ? `マルウェア` : (b.scans.AutoShun.result === `phishing site`) ? `フィッシング` : (b.scans.AutoShun.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`CyRadar`, (b.scans.CyRadar.result === `malicious site` || b.scans.CyRadar.result === `malware site`) ? `マルウェア` : (b.scans.CyRadar.result === `phishing site`) ? `フィッシング` : (b.scans.CyRadar.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Forcepoint ThreatSeeker`, (b.scans[`Forcepoint ThreatSeeker`].result === `malicious site` || b.scans[`Forcepoint ThreatSeeker`].result === `malware site`) ? `マルウェア` : (b.scans[`Forcepoint ThreatSeeker`].result === `phishing site`) ? `フィッシング` : (b.scans[`Forcepoint ThreatSeeker`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Malware Domain Blocklist`, (b.scans[`Malware Domain Blocklist`].result === `malicious site` || b.scans[`Malware Domain Blocklist`].result === `malware site`) ? `マルウェア` : (b.scans[`Malware Domain Blocklist`].result === `phishing site`) ? `フィッシング` : (b.scans[`Malware Domain Blocklist`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Rising`, (b.scans.Rising.result === `malicious site` || b.scans.Rising.result === `malware site`) ? `マルウェア` : (b.scans.Rising.result === `phishing site`) ? `フィッシング` : (b.scans.Rising.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Spam404`, (b.scans.Spam404.result === `malicious site` || b.scans.Spam404.result === `malware site`) ? `マルウェア` : (b.scans.Spam404.result === `phishing site`) ? `フィッシング` : (b.scans.Spam404.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Dr.Web`, (b.scans[`Dr.Web`].result === `malicious site` || b.scans[`Dr.Web`].result === `malware site`) ? `マルウェア` : (b.scans[`Dr.Web`].result === `phishing site`) ? `フィッシング` : (b.scans[`Dr.Web`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`MalwareDomainList`, (b.scans.MalwareDomainList.result === `malicious site` || b.scans.MalwareDomainList.result === `malware site`) ? `マルウェア` : (b.scans.MalwareDomainList.result === `phishing site`) ? `フィッシング` : (b.scans.MalwareDomainList.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`G-Data`, (b.scans[`G-Data`].result === `malicious site` || b.scans[`G-Data`].result === `malware site`) ? `マルウェア` : (b.scans[`G-Data`].result === `phishing site`) ? `フィッシング` : (b.scans[`G-Data`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Malc0de Database`, (b.scans[`Malc0de Database`].result === `malicious site` || b.scans[`Malc0de Database`] === `malware site`) ? `マルウェア` : (b.scans[`Malc0de Database`].result === `phishing site`) ? `フィッシング` : (b.scans[`Malc0de Database`].result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`DNS8`, (b.scans.DNS8.result === `malicious site` || b.scans.DNS8.result === `malware site`) ? `マルウェア` : (b.scans.DNS8.result === `phishing site`) ? `フィッシング` : (b.scans.DNS8.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Quttera`, (b.scans.Quttera.result === `malicious site` || b.scans.Quttera.result === `malware site`) ? `マルウェア` : (b.scans.Quttera.result === `phishing site`) ? `フィッシング` : (b.scans.Quttera.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Phishtank`, (b.scans.Phishtank.result === `malicious site` || b.scans.Phishtank.result === `malware site`) ? `マルウェア` : (b.scans.Phishtank.result === `phishing site`) ? `フィッシング` : (b.scans.Phishtank.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Trustwave`, (b.scans.Trustwave.result === `malicious site` || b.scans.Trustwave.result === `malware site`) ? `マルウェア` : (b.scans.Trustwave.result === `phishing site`) ? `フィッシング` : (b.scans.Trustwave.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .addField(`Emsisoft`, (b.scans.Emsisoft.result === `malicious site` || b.scans.Emsisoft.result === `malware site`) ? `マルウェア` : (b.scans.Emsisoft.result === `phishing site`) ? `フィッシング` : (b.scans.Emsisoft.result === `suspicious site`) ? `怪しい動作` : `未検出`, true)
                                            .setFooter(`Powered By VirusTotal and Google Safebrowsing | https://virustotal.com https://safebrowsing.google.com`)
                                            .setColor(`#7289da`)
                                    );

                                } else {

                                    m.author.send(
                                        new Discord.RichEmbed()
                                            .setTitle(`スキャン結果`)
                                            .setDescription(`URL: ${m.content.slice(s[0].length + 2)}\nURL をスキャンしようとしましたがデータベースが不足しているため、 Google Safebrowsing のスキャン結果だけとなります`)
                                            .addField(`Google Safebrowsing`, (body.matches === undefined) ? `未検出` : (body.matches[0].threatType === `MALWARE`) ? `マルウェア` : (body.matches[0].threatType === `SOCIAL_ENGINEERING`) ? `フィッシング` : `不明`, true)
                                            .setFooter(`Powered By Google Safebrowsing | https://safebrowsing.google.com`, `https://developers.google.com/safe-browsing/images/SafeBrowsing_Icon.png`)
                                            .setColor(`#7289da`)

                                    );

                                }

                            });

                        });

                    } else {

                        m.channel.send(`スキャンしたい URL を入力してください`);

                    }

                }
            } else if (m.content.startsWith(`: `)) {

                sendMessage(m, Message.Text, `コンパクトモード使ってるでしょ`);

            } else if (m.content.startsWith(`!disboard bump`)) {

                sendMessage(m, Message.Text, `下げました:thumbsup:`);

            } else if (m.content.startsWith(`!discha-update`)) {

                sendMessage(m, Message.Text, `サーバー情報が削除されました。`);

            }

        }

    });

}).on(`disconnect`, (m) => {
    console.log(`Discord との接続が切断されました`);
    Disconnected = true;

}).on(`reconnecting`, (m) => {
    console.log(`再接続を試みています...`);
    Disconnected = true;
});

Client.login(Config.Discord);
