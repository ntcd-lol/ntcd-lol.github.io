// clientAPI.js

class MeshAPI {
    constructor() {
        // Добавь сюда свой домен loca.lt, который ты запускаешь
        this.possibleDomains = [
            "https://mesh.loca.lt", 
            "https://mesh.instatunnel.me",
            "https://meshmesh.instatunnel.me"
        ];
        this.baseUrl = null;
        this.user = null;
        this.currentChannel = null;
        this.cryptoKey = null;
    }

    // Вспомогательный метод для заголовков
    // 'Bypass-Tunnel-Reminder': 'true' — это КЛЮЧ к решению проблемы с loca.lt
    getHeaders() {
        return {
            'Content-Type': 'application/json',
            'Bypass-Tunnel-Reminder': 'true' 
        };
    }

    async findServer() {
        console.log("🔍 Searching for mesh node...");
        for (let domain of this.possibleDomains) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 сек таймаут
                
                // Для GET запроса заголовки тоже нужны, чтобы пройти проверку туннеля
                const response = await fetch(`${domain}/`, { 
                    signal: controller.signal,
                    headers: { 'Bypass-Tunnel-Reminder': 'true' }
                });
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

    // Хеширование (безопасность от Chrome)
    async hashPassword(password) {
        const msgBuffer = new TextEncoder().encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    async register(username, password) {
        const passwordHash = await this.hashPassword(password);
        
        const res = await fetch(`${this.baseUrl}/api/register`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({username, password: passwordHash})
        });
        if (!res.ok) throw new Error(await res.text());
        return await res.json();
    }

    async login(username, password) {
        const passwordHash = await this.hashPassword(password);

        const res = await fetch(`${this.baseUrl}/api/login`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({username, password: passwordHash})
        });
        if (!res.ok) throw new Error("Login failed");
        this.user = await res.json();
        return this.user;
    }

    async joinChannel(channelName) {
        const res = await fetch(`${this.baseUrl}/api/channel/join`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({channel_name: channelName})
        });
        const data = await res.json();
        this.currentChannel = data.channel;
        return data; 
    }

    // --- Encryption (без изменений) ---
    async setChannelKey(secretPhrase) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", enc.encode(secretPhrase), {name: "PBKDF2"}, false, ["deriveKey"]
        );
        this.cryptoKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2", salt: enc.encode("mesh_salt_static"),
                iterations: 100000, hash: "SHA-256"
            },
            keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
        );
    }

    async encryptMessage(text) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, this.cryptoKey, enc.encode(text)
        );
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
                { name: "AES-GCM", iv: iv }, this.cryptoKey, data
            );
            return new TextDecoder().decode(decrypted);
        } catch (e) { return "🔒 [Encrypted / Bad Key]"; }
    }
}
