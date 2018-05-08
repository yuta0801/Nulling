const Discord = require(`discord.js`),
    YTDL = require(`ytdl-core`),
    Client = new Discord.Client(),
    Config = require(`./config.json`),
    Token = Config.Token,
    Version = Config.Version,
    Prefix = `-`;

Client.on(`ready`, () => {
    console.log(`---ログインが完了しました---\nトークン: ${Token.slice(0, 10)}${`*`.repeat(Token.length - 10)}\nタグ: ${Client.user.tag}\nID: ${Client.user.id}\n---ログインが完了しました---`);
});

Client.on(`message`, (m) => {
    if (m.author.bot) return;
    if (!m.content.startsWith(Prefix)) return;
    console.log(m.content);
});

Client.login(Token);
