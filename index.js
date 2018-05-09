"use strict";

const Discord = require(`discord.js`),
    YTDL = require(`ytdl-core`),
    Client = new Discord.Client(),
    Config = require(`./config/config.json`),
    ja_jp = require(`./ja_jp/lang.json`),
    Token = Config.Token,
    Version = Config.Version,
    Prefix = `-`,
    Lang = `ja_jp`,
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
    sendMessage = (Message, DataCode, AttData) => {
        if (Message && DataCode) {
            for (let i = 0; i < Object.keys(AttData).length; i++) {
                Message.channel.send(ja_jp.command.ping.success.replace(`%s%${Object.keys(AttData)[i]}`, AttData[Object.keys(AttData)[i]]));
            }
        } else if (!Message & DataCode) {
            Error.Record(`sendMessage`, Error.Missing, `Message, DataCode`, getCallStack());
        } else if (!Message) {
            Error.Record(`sendMessage`, Error.Missing, `Message`, getCallStack());
        } else if (!DataCode) {
            Error.Record(`sendMessage`, Error.Missing, `DataCode`, getCallStack());
        }
    },
    CallStack = () => {
        try {
            throw new Error(`Dummy`);
        } catch (Content) {
            return Content.stack.split(`\n`)[2].split(`(`)[1].replace(`)`, ``);
        }
    };

let Ping = 0,
    Launched = false;

Client.on(`ready`, () => {
    Client.user.setActivity(`Ping を確認しています...`, { type: `STREAMING` });
    setTimeout(() => {
        Launched = true;
        Ping = Client.ping;
        console.log(`---ログインが完了しました---\nトークン: ${Token.slice(0, 20)}${`*`.repeat(Token.length - 20)}\nタグ: ${Client.user.tag}\nID: ${Client.user.id}\nPing: ${Ping}\n---ログインが完了しました---\n`);
        setTimeout(() => {
            Client.user.setActivity(`Ping is ${Ping}ms`, { type: `STREAMING` });
        }, 3000);
    }, 1000);
    setInterval(() => {
        Ping = Client.ping;
        Client.user.setActivity(`Ping を確認しています...`, { type: `STREAMING` });
        setTimeout(() => {
            Client.user.setActivity(`Ping is ${Ping}ms`, { type: `STREAMING` });
        }, 3000);
    }, 30000);
}).on(`message`, (m) => {
    if (!Launched) return;
    if (m.author.bot) return;
    if (!m.content.startsWith(Prefix)) return;
    const s = m.content.slice(Prefix.length).split(` `);
    if (s[0] == `ping`) {
        sendMessage(m, [`command`, `ping`, `success`], { "ping": Ping });
    }
});

Client.login(Token);
