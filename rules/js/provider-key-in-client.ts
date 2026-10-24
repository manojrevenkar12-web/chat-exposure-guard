import OpenAI from "openai";

// ruleid: ceg.provider-key-in-client
const client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_KEY, dangerouslyAllowBrowser: true });

// ruleid: ceg.provider-key-in-client
const other = new Anthropic({ apiKey: "sk-ant-0123456789abcdefghijABCD" });

// ok: ceg.provider-key-in-client
const server = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
