"use strict";

const Discord = require(`discord.js`),
    YTDL = require(`ytdl-core`),
    Client = new Discord.Client(),
    Config = require(`./config/private.json`),
    Token = Config.Token,
    Version = Config.Version,
    Prefix = `-`,

    Language = {
        "en_us": {
            "main": require(`./en_us/main.json`),
            "changelog": require(`./en_us/changelog.json`)
        },
        "ja_jp": {
            "main": require(`./ja_jp/main.json`),
            "changelog": require(`./ja_jp/changelog.json`)
        }
    },

    l = Language.ja_jp.main,

    StatusMessage = [
        `Developed by NULL Code JP#6593`,
        `Type "-help" to show help`,
        `Today is ${[`Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`, `Saturday`][new Date().getDay()]}.`,
        `"Hello" in Japanese is "こんにちは"`,
        `This is a pen.`,
        `WINNER WINNER CHICKEN DINNER!`,
        `我現在很累。`,
        `ง่วงนอน...`,
        `Ich bin jetzt live.`,
        `Uhh... I can't think status messages.`,
        `あいうえお`,
        `Can you see me?`,
        `I'm using Firefox.`,
        `https://djs-jpn.ga (Japanese only. Sorry...)`,
        `This status message is random.`,
        `元気？`
    ],

    Error = {
        Missing: `Missing`,
        Record: (Function, Type, Content, Stack) => {
            if (Type === `Missing`) {
                console.error(`\u001b[31m関数 ${Function} でエラーが発生しました：引数 ${Content} が足りません。\u001b[0m\nエラーの発生源：${Stack}`);
            } else if (Type === `Invalid`) {
                console.error(`\u001b[31m関数 ${Function} でエラーが発生しました：引数 ${Content} が無効です。\u001b[0m\nエラーの発生源：${Stack}`);
            } else {
                console.error(`\u001b[31m関数 Error.Record でエラーが発生しました：引数 Type が無効です。\u001b[0m\nエラーの発生源：${CallStack()}`);
            }
        }
    },

    Message = {
        Text: `Text`,
        Embed: `Embed`
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
                        .setColor(`#FFFFFF`)
                );
            } else {
                Error.Record(`sendMessage`, Error.Invalid, `Type`, CallStack());
            }
        } else {
            if (!Message) {
                Error.Record(`sendMessage`, Error.Missing, `Message`, CallStack());
            }
            if (!Type) {
                Error.Record(`sendMessage`, Error.Missing, `Type`, CallStack());
            }
            if (!DataCode) {
                Error.Record(`sendMessage`, Error.Missing, `DataCode`, CallStack());
            }
        }
    },

    v = (DataCode, AttData, AttData2, AttData3) => {
        return DataCode.replace(`%s%1;`, AttData).replace(`%s%2;`, AttData2).replace(`%s%3;`, AttData3);
    },

    CallStack = () => {
        try {
            throw new Error(`Dummy`);
        } catch (Content) {
            return Content.stack.split(`\n`)[3].split(`(`)[1].replace(`)`, ``);
        }
    };

let Ping = 0,
    Launched = false,
    Disconnected = false;

Client.on(`ready`, () => {
    if (Disconnected) {
        console.log(`再接続に成功しました。`);
    }
    Client.user.setActivity(`Developed by NULL Code JP#6593`, { type: `STREAMING` });

    console.log(`ボットが安定するまで待機しています...\n`);

    setTimeout(() => {
        Ping = Math.floor(Client.ping);
    }, 500);

    setTimeout(() => {
        Launched = true;
        console.log(`---ログインが完了しました---\nトークン: ${Token.slice(0, 20)}${`*`.repeat(Token.length - 20)}\nタグ: ${Client.user.tag}\nID: ${Client.user.id}\nPing: ${Ping}ms\n---ログインが完了しました---\n`);
    }, 1000);

    setInterval(() => {
        Ping = Math.floor(Client.ping);
        Client.user.setActivity(StatusMessage[Math.floor(Math.random() * StatusMessage.length)], { type: `STREAMING` });
    }, 30000);

}).on(`message`, (m) => {
    if (!Launched) return;
    if (m.author.bot) return;
    if (!m.content.startsWith(Prefix)) return;

    const s = m.content.slice(Prefix.length).split(` `);

    if (s[0] === `ping`) {

        sendMessage(m, Message.Text, l.commands.ping.success, Ping, Date.now() - m.createdTimestamp);

    } else if (s[0] === `help`) {

        if (s[1] === `help`) {

            m.channel.send(
                new Discord.RichEmbed()
                    .setTitle(`help (${l.commands.help.details.help.name})`)
                    .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                    .setDescription(l.commands.help.details.help.description)
                    .addField(l.commands.help.subcommand, `-help [${l.commands.help.details.help.subcommands.cmdname.name}]: ${l.commands.help.details.help.subcommands.cmdname.description}`)
                    .setColor(`#FFFFFF`)
            );

        } else if (s[1] === undefined) {

            m.channel.send(
                new Discord.RichEmbed()
                    .setTitle(l.commands.help.title)
                    .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                    .setDescription(l.commands.help.tips)
                    .addField(l.commands.help.categories.bot, `\`help\` \`ping\``, true)
                    .addField(l.commands.help.categories.utils, `\`qrcode\``, true)
                    .setColor(`#FFFFFF`)
            );

        }

    } else if (s[0] === `qrcode`) {

        if (s[1]) {

            if (s[1] === `UTF-8` || s[1] === `Shift_JIS` || s[1] === `ISO-8859-1`) {

            } else {
                sendMessage(m, Message.Text, l.commands.qrcode.error.two);
            }
            if (s[2]) {

                m.channel.send(
                    new Discord.RichEmbed()
                        .setTitle(l.commands.qrcode.success)
                        .setAuthor(`@${m.author.tag}`, m.author.avatarURL)
                        .setDescription(`${l.commands.qrcode.imagelink}https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${s[2]}&choe=${s[1]}&chld=H|1`)
                        .setImage(`https://chart.apis.google.com/chart?cht=qr&chs=547x547&chl=${s[2]}&choe=${s[1]}&chld=H|1`)
                        .setColor(`#FFFFFF`)
                );

            } else {
                sendMessage(m, Message.Text, l.commands.qrcode.error.three);
            }

        } else {
            sendMessage(m, Message.Text, l.commands.qrcode.error.one);
        }
    }

}).on(`disconnect`, (m) => {
    console.log(`Discord との接続が切断されました。`);
    Disconnected = true;

}).on(`reconnecting`, (m) => {
    console.log(`再接続を試みています...`);
    Disconnected = true;
});

Client.login(Token);
