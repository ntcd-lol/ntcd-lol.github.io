// clientAPI.js

class MeshAPI {
    constructor() {
        this.possibleDomains = [
            "https://mesh.loca.lt",
            "https://meshmesh.loca.lt",
            "https://ntcdlol.loca.lt"
        ];
        this.baseUrl = null;
        this.user = null;
        this.currentChannel = null;
        this.cryptoKey = null; // Ключ для шифрования сообщений
    }

    // Поиск живого сервера
    async findServer() {
        console.log("🔍 Searching for mesh node...");
        for (let domain of this.possibleDomains) {
            try {
                // Используем AbortController для быстрого таймаута
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 2000);
                
                const response = await fetch(`${domain}/`, { signal: controller.signal });
                clearTimeout(timeoutId);

                if (response.ok) {
                    const data = await response.json();
                    if (data.status === "mesh_online") {
                        this.baseUrl = domain;
                        console.log(`✅ Connected to node: ${domain}`);
                        return domain;
                    }
                }
            } catch (e) {
                console.warn(`❌ Node ${domain} unreachable`);
            }
        }
        throw new Error("No mesh nodes available");
    }

    async register(username, password) {
        const res = await fetch(`${this.baseUrl}/api/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        if (!res.ok) throw new Error(await res.text());
        return await res.json();
    }

    async login(username, password) {
        const res = await fetch(`${this.baseUrl}/api/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        if (!res.ok) throw new Error("Login failed");
        this.user = await res.json();
        return this.user;
    }

    async joinChannel(channelName) {
        const res = await fetch(`${this.baseUrl}/api/channel/join`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({channel_name: channelName})
        });
        const data = await res.json();
        this.currentChannel = data.channel;
        return data; // returns {channel, history}
    }

    // --- Encryption Utils (AES-GCM) ---
    // Генерируем ключ из пароля канала (Shared Secret)
    async setChannelKey(secretPhrase) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", enc.encode(secretPhrase), {name: "PBKDF2"}, false, ["deriveKey"]
        );
        this.cryptoKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2", salt: enc.encode("mesh_salt_static"), // В идеале соль должна быть случайной
                iterations: 100000, hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true, ["encrypt", "decrypt"]
        );
    }

    async encryptMessage(text) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            this.cryptoKey,
            enc.encode(text)
        );
        
        // Упаковываем IV и данные в Base64 строку
        const ivArr = Array.from(iv);
        const dataArr = Array.from(new Uint8Array(encrypted));
        return JSON.stringify({iv: ivArr, data: dataArr});
    }

    async decryptMessage(jsonString) {
        try {
            const raw = JSON.parse(jsonString);
            const iv = new Uint8Array(raw.iv);
            const data = new Uint8Array(raw.data);
            
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                this.cryptoKey,
                data
            );
            const dec = new TextDecoder();
            return dec.decode(decrypted);
        } catch (e) {
            return "🔒 [Encrypted / Bad Key]";
        }
    }
}
