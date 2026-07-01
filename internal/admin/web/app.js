// Yvonne KMS Web Console — Vue 3 SPA
const { createApp, ref, reactive, onMounted, computed } = Vue
const { createRouter, createWebHistory } = VueRouter

// === API Client ===
const api = {
    token: localStorage.getItem('yvonne_token') || '',
    base: '',

    async request(method, path, body) {
        const headers = { 'Content-Type': 'application/json' }
        if (this.token) headers['Authorization'] = 'Bearer ' + this.token
        const resp = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null })
        const data = await resp.json()
        if (!data.ok) throw new Error(data.error || 'Unknown error')
        return data.data || data
    },

    get(path) { return this.request('GET', path) },
    post(path, body) { return this.request('POST', path, body) },
    del(path) { return this.request('DELETE', path) },

    // Dashboard
    dashboard() { return this.get('/admin/api/dashboard') },

    // Keys
    listKeys() { return this.get('/admin/api/keys') },

    // Audit
    audit() { return this.get('/admin/api/audit') },
}

// === Components ===
const Dashboard = {
    template: `
    <div>
        <h2 class="text-2xl font-bold mb-6">Dashboard</h2>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-500">Key Count</div>
                <div class="text-3xl font-bold text-blue-600 mt-2">{{ stats.key_count || 0 }}</div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-500">Vault State</div>
                <div class="text-3xl font-bold mt-2" :class="stats.sealed ? 'text-red-600' : 'text-green-600'">
                    {{ stats.state || 'unknown' }}
                </div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <div class="text-sm text-gray-500">Sealed</div>
                <div class="text-3xl font-bold mt-2" :class="stats.sealed ? 'text-red-600' : 'text-green-600'">
                    {{ stats.sealed ? 'Yes' : 'No' }}
                </div>
            </div>
        </div>
    </div>
    `,
    setup() {
        const stats = ref({})
        onMounted(async () => {
            try { stats.value = await api.dashboard() } catch(e) { console.error(e) }
        })
        return { stats }
    }
}

const KeyList = {
    template: `
    <div>
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Keys</h2>
            <button @click="refresh" class="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">Refresh</button>
        </div>
        <div v-if="loading" class="text-gray-500">Loading...</div>
        <div v-else-if="keys.length === 0" class="text-gray-500">No keys found.</div>
        <table v-else class="w-full bg-white rounded-lg shadow">
            <thead class="bg-gray-100">
                <tr>
                    <th class="text-left px-4 py-3">Key ID</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="key in keys" :key="key.key_id" class="border-t">
                    <td class="px-4 py-3 font-mono text-sm">{{ key.key_id }}</td>
                </tr>
            </tbody>
        </table>
    </div>
    `,
    setup() {
        const keys = ref([])
        const loading = ref(true)

        const refresh = async () => {
            loading.value = true
            try {
                const data = await api.listKeys()
                keys.value = data.keys || []
            } catch(e) { console.error(e) }
            loading.value = false
        }

        onMounted(refresh)
        return { keys, loading, refresh }
    }
}

const CryptoTool = {
    template: `
    <div>
        <h2 class="text-2xl font-bold mb-6">Crypto Tool</h2>
        <div class="bg-white rounded-lg shadow p-6">
            <p class="text-gray-500 mb-4">Connect to API endpoints for encrypt/decrypt/sign/verify/MAC testing.</p>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Key ID</label>
                    <input v-model="keyId" type="text" class="w-full px-3 py-2 border rounded" placeholder="key-id">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Data (plaintext)</label>
                    <textarea v-model="data" class="w-full px-3 py-2 border rounded" rows="3" placeholder="data to encrypt"></textarea>
                </div>
                <button @click="encrypt" class="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600">Encrypt</button>
                <div v-if="result" class="mt-4 p-4 bg-gray-100 rounded">
                    <pre class="text-sm overflow-auto">{{ result }}</pre>
                </div>
            </div>
        </div>
    </div>
    `,
    setup() {
        const keyId = ref('')
        const data = ref('')
        const result = ref('')

        const encrypt = async () => {
            try {
                result.value = 'Use POST /api/v1/encrypt with Bearer token to encrypt.'
            } catch(e) { result.value = e.message }
        }

        return { keyId, data, result, encrypt }
    }
}

const AuditLog = {
    template: `
    <div>
        <h2 class="text-2xl font-bold mb-6">Audit Log</h2>
        <div v-if="loading" class="text-gray-500">Loading...</div>
        <div v-else-if="entries.length === 0" class="text-gray-500">No audit entries.</div>
        <table v-else class="w-full bg-white rounded-lg shadow">
            <thead class="bg-gray-100">
                <tr>
                    <th class="text-left px-4 py-3">Timestamp</th>
                    <th class="text-left px-4 py-3">Action</th>
                    <th class="text-left px-4 py-3">Actor</th>
                    <th class="text-left px-4 py-3">Result</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="(entry, i) in entries" :key="i" class="border-t">
                    <td class="px-4 py-3 text-sm">{{ entry.timestamp || '-' }}</td>
                    <td class="px-4 py-3 text-sm font-mono">{{ entry.action || '-' }}</td>
                    <td class="px-4 py-3 text-sm">{{ entry.actor || '-' }}</td>
                    <td class="px-4 py-3 text-sm">{{ entry.result || '-' }}</td>
                </tr>
            </tbody>
        </table>
    </div>
    `,
    setup() {
        const entries = ref([])
        const loading = ref(true)

        onMounted(async () => {
            try {
                const data = await api.audit()
                entries.value = data.entries || []
            } catch(e) { console.error(e) }
            loading.value = false
        })

        return { entries, loading }
    }
}

const MfaQuorum = {
    template: `
    <div>
        <h2 class="text-2xl font-bold mb-6">MFA & Quorum</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="font-bold text-lg mb-4">MFA Status</h3>
                <p class="text-gray-500">Use POST /api/v1/auth/mfa/setup to register TOTP.</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="font-bold text-lg mb-4">Quorum Approvals</h3>
                <p class="text-gray-500">Use GET /api/v1/approvals to list pending tickets.</p>
            </div>
        </div>
    </div>
    `
}

// === Router ===
const routes = [
    { path: '/', component: Dashboard },
    { path: '/keys', component: KeyList },
    { path: '/crypto', component: CryptoTool },
    { path: '/audit', component: AuditLog },
    { path: '/mfa', component: MfaQuorum },
]

const router = createRouter({
    history: createWebHistory(),
    routes,
})

// === App ===
const app = createApp({
    template: `
    <div>
        <nav class="bg-gray-800 text-white px-6 py-3 flex items-center justify-between">
            <div class="flex items-center space-x-6">
                <router-link to="/" class="font-bold text-lg">Yvonne KMS</router-link>
                <router-link to="/keys" class="hover:text-blue-300">Keys</router-link>
                <router-link to="/crypto" class="hover:text-blue-300">Crypto</router-link>
                <router-link to="/audit" class="hover:text-blue-300">Audit</router-link>
                <router-link to="/mfa" class="hover:text-blue-300">MFA & Quorum</router-link>
            </div>
            <div class="flex items-center space-x-2">
                <input v-model="api.token" @input="saveToken" type="password" placeholder="Bearer Token"
                    class="px-2 py-1 text-black rounded text-sm w-48">
            </div>
        </nav>
        <main class="max-w-7xl mx-auto px-6 py-8">
            <router-view></router-view>
        </main>
    </div>
    `,
    setup() {
        const saveToken = () => {
            localStorage.setItem('yvonne_token', api.token)
        }
        return { api, saveToken }
    }
})

app.use(router)
app.mount('#app')
