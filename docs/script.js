// ===== Constants =====
const ThreatLevels = {
    SAFE: { name: 'SAFE', color: 'safe', icon: 'check_circle' },
    SUSPICIOUS: { name: 'WARNING', color: 'warning', icon: 'warning' },
    DANGER: { name: 'DANGER', color: 'danger', icon: 'gpp_bad' }
};

// ===== AI Backend API Config =====
const API_BASE = 'http://localhost:8000';
let isApiConnected = false;
let pollInterval = null;
let knownStreamIds = new Set();   // Prevent duplicate stream threats on dashboard

const Platforms = {
    WHATSAPP: { id: 'whatsapp', label: 'WhatsApp', icon: 'chat', color: '#25D366', bg: 'rgba(37,211,102,0.15)' },
    INSTAGRAM: { id: 'instagram', label: 'Instagram', icon: 'photo_camera', color: '#E1306C', bg: 'rgba(225,48,108,0.15)' },
    TELEGRAM: { id: 'telegram', label: 'Telegram', icon: 'send', color: '#2AABEE', bg: 'rgba(42,171,238,0.15)' },
    SMS: { id: 'sms', label: 'SMS', icon: 'sms', color: '#FFD600', bg: 'rgba(255,214,0,0.15)' },
    EMAIL: { id: 'email', label: 'Email', icon: 'email', color: '#FF6B35', bg: 'rgba(255,107,53,0.15)' },
    APP: { id: 'app', label: 'App', icon: 'apps', color: '#A855F7', bg: 'rgba(168,85,247,0.15)' },
    NETWORK: { id: 'network', label: 'Network', icon: 'wifi', color: '#0052FF', bg: 'rgba(0,82,255,0.15)' }
};

// ===== Mock Threat Data =====
const mockThreats = [
    // WhatsApp
    {
        id: '1',
        platform: Platforms.WHATSAPP,
        source: 'WhatsApp: +91-98XXXXXXXX',
        contentPreview: '🎉 Congratulations! You won ₹50,000 in KBC. Claim now: bit.ly/kbc-fake',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 1800000),
        details: 'Classic lottery scam via WhatsApp. The link leads to a credential-harvesting page mimicking the KBC brand. Never click links in unsolicited prize messages.',
        tags: ['Lottery Scam', 'Phishing Link', 'Urgency Tactic']
    },
    {
        id: '2',
        platform: Platforms.WHATSAPP,
        source: 'WhatsApp: Unknown Contact',
        contentPreview: 'Your bank OTP is 847293. Forward this to confirm your account.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 7200000),
        details: 'OTP theft attempt. Legitimate banks never ask you to forward OTPs over WhatsApp. The sender is attempting to hijack your bank account.',
        tags: ['OTP Theft', 'Social Engineering', 'Bank Fraud']
    },
    {
        id: '3',
        platform: Platforms.WHATSAPP,
        source: 'WhatsApp Group: "Job Offers 2026"',
        contentPreview: 'Work from home, earn ₹5000/day. No experience needed. Join fee ₹500 only.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 10800000),
        details: 'Fake job offer scam targeting unemployed individuals. The "registration fee" is never returned and no legitimate job is provided.',
        tags: ['Job Scam', 'Advance Fee Fraud']
    },
    // Instagram
    {
        id: '4',
        platform: Platforms.INSTAGRAM,
        source: 'Instagram DM: @nike_official_giveaway',
        contentPreview: '🎁 You\'ve been selected for Nike\'s 50th anniversary giveaway. Click to claim your free shoes!',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 3600000),
        details: 'Impersonation of Nike brand on Instagram. The account handle is fake (real Nike handle has blue verification). Clicking leads to a credential phishing page.',
        tags: ['Brand Impersonation', 'Phishing', 'Fake Giveaway']
    },
    {
        id: '5',
        platform: Platforms.INSTAGRAM,
        source: 'Instagram DM: @sarah_love_2026',
        contentPreview: 'Hey, I love your profile! I\'m a model in Dubai. Can we connect? I have a business opportunity for you.',
        level: ThreatLevels.SUSPICIOUS,
        timestamp: new Date(Date.now() - 86400000),
        details: 'Likely a romance scam. Fraudsters build emotional trust before requesting money for "emergencies" or "travel". Profile appears recently created with stock images.',
        tags: ['Romance Scam', 'Social Engineering']
    },
    {
        id: '6',
        platform: Platforms.INSTAGRAM,
        source: 'Instagram: Login Alert',
        contentPreview: 'Your account was accessed from New York. Click to secure your Instagram account now.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 43200000),
        details: 'Phishing email posing as Instagram security alert. The link leads to a fake login page designed to steal your Instagram credentials.',
        tags: ['Account Takeover', 'Credential Phishing']
    },
    // Telegram
    {
        id: '7',
        platform: Platforms.TELEGRAM,
        source: 'Telegram: Crypto Profit Bot',
        contentPreview: '📈 Invest ₹10,000 today, earn ₹40,000 in 7 days! 400% guaranteed returns. Limited slots!',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 5400000),
        details: 'Cryptocurrency investment fraud. No legitimate investment guarantees fixed returns. Victims are shown fake profit dashboards before the platform disappears with their funds (exit scam / pig butchering).',
        tags: ['Crypto Fraud', 'Investment Scam', 'Pig Butchering']
    },
    {
        id: '8',
        platform: Platforms.TELEGRAM,
        source: 'Telegram: "Paytm Support Official"',
        contentPreview: 'Your Paytm account requires verification. Send your Aadhaar number and selfie to complete KYC.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 14400000),
        details: 'Fake customer support impersonating Paytm. Legitimate companies never request Aadhaar or selfies via Telegram. This is identity theft preparation.',
        tags: ['Identity Theft', 'KYC Fraud', 'Impersonation']
    },
    {
        id: '9',
        platform: Platforms.TELEGRAM,
        source: 'Telegram: file_hacked.apk',
        contentPreview: 'Install this APK to access premium content for free. 100% safe!',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 21600000),
        details: 'Malicious APK distributed via Telegram. Installation grants attacker remote access, reads SMS (OTPs), and exfiltrates banking credentials. Never install APKs from unknown sources.',
        tags: ['Malware', 'Spyware', 'RAT']
    },
    // SMS
    {
        id: '10',
        platform: Platforms.SMS,
        source: 'SMS: +1-555-0123',
        contentPreview: 'Your package delivery failed. Check here: http://bit.ly/sus_link',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 28800000),
        details: 'Smishing (SMS phishing) targeting delivery service customers. URL redirects to a fake courier site requesting card details for "re-delivery fee".',
        tags: ['Smishing', 'Delivery Fraud']
    },
    {
        id: '11',
        platform: Platforms.SMS,
        source: 'SMS: VDFONE',
        contentPreview: 'URGENT: Your SIM card will be blocked in 24hrs. Call 09XXXXXXXX to prevent deactivation.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 50400000),
        details: 'SIM swap fraud initiation. Calling the number connects victim to a fraudster posing as a telecom executive who extracts OTPs to perform a SIM swap and drain bank accounts.',
        tags: ['SIM Swap', 'Telecom Fraud']
    },
    // Email
    {
        id: '12',
        platform: Platforms.EMAIL,
        source: 'Email: update@bank.security.com',
        contentPreview: 'Important change to your account terms. Login required.',
        level: ThreatLevels.SUSPICIOUS,
        timestamp: new Date(Date.now() - 72000000),
        details: 'Sender address mimics a known institution but fails SPF/DKIM checks. The domain "bank.security.com" is not associated with any legitimate bank.',
        tags: ['Email Spoofing', 'Phishing']
    },
    {
        id: '13',
        platform: Platforms.EMAIL,
        source: 'Email: ceo@companiy-corp.com',
        contentPreview: 'Hi, I need you to urgently transfer ₹2,50,000 to this account. Do not discuss with anyone.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 90000000),
        details: 'Business Email Compromise (BEC). Fraudster impersonates a CEO or senior executive to authorize fraudulent wire transfers. Note the domain misspelling: "companiy-corp.com".',
        tags: ['BEC', 'CEO Fraud', 'Wire Transfer Fraud']
    },
    // App / Network
    {
        id: '14',
        platform: Platforms.APP,
        source: 'App: Unknown Scanner',
        contentPreview: 'App requesting Camera, Contacts, SMS permissions in background.',
        level: ThreatLevels.DANGER,
        timestamp: new Date(Date.now() - 172800000),
        details: 'App behavior matches known spyware signatures. Excessive permissions requested without user prompt. Uninstall immediately.',
        tags: ['Spyware', 'Permission Abuse']
    },
    {
        id: '15',
        platform: Platforms.NETWORK,
        source: 'System: Network Change',
        contentPreview: "Connected to unsecured Wi-Fi 'Free Airport Wifi'",
        level: ThreatLevels.SUSPICIOUS,
        timestamp: new Date(Date.now() - 259200000),
        details: 'Traffic on this network appears unencrypted. A man-in-the-middle attack could intercept your banking sessions. Use a VPN immediately.',
        tags: ['MITM Risk', 'Unsecured Network']
    }
];

const mockTips = [
    { icon: 'chat', platform: 'WhatsApp', title: "Never Forward OTPs on WhatsApp", description: "Banks, Aadhaar, and government agencies will NEVER ask for your OTP via WhatsApp. Forwarding OTPs is the #1 way bank accounts are drained." },
    { icon: 'photo_camera', platform: 'Instagram', title: "Verify Giveaways via Official Pages", description: "Fake brand accounts run giveaway scams. Always verify by checking if the account has a blue tick and matching follower count on the brand's real profile." },
    { icon: 'send', platform: 'Telegram', title: "No Legitimate Investment Has '400% Returns'", description: "Crypto bots on Telegram promising guaranteed returns are always scams. Real investments carry risk. Never invest money you can't afford to lose with strangers online." },
    { icon: 'sms', platform: 'SMS', title: "Treat Urgent SMS as a Red Flag", description: "Smishing messages use urgency ('Your SIM will block in 24hrs'). Call your operator's official number directly — never the one in the SMS." },
    { icon: 'verified_user', platform: 'General', title: "Enable Two-Factor Authentication (2FA)", description: "Add an extra layer to all accounts. Even if your password is stolen, attackers cannot log in without your physical device." },
    { icon: 'wifi_off', platform: 'Network', title: "Use a VPN on Public Wi-Fi", description: "Unsecured public networks expose your data. Use a trusted VPN app before accessing email, banking, or social media on public Wi-Fi." },
    { icon: 'face', platform: 'General', title: "Beware of Deepfakes in Video Calls", description: "AI can now clone faces and voices. If you get a video call asking for money — even from a known contact — hang up and call them back on a known number." },
    { icon: 'shield', platform: 'General', title: "Keep Apps Updated", description: "Security patches often fix critical vulnerabilities. Enable auto-updates for all your apps and your operating system." },
    { icon: 'no_sim', platform: 'SIM', title: "Set a SIM Lock PIN", description: "A SIM lock PIN prevents a stolen phone from being used to receive OTPs. Set one in your phone's Security settings." },
    { icon: 'email', platform: 'Email', title: "Check the Exact Sender Domain", description: "Phishers use 'companiy.com' or 'bank-secure-login.com'. Hover over the sender name to reveal the true email address before clicking any link." }
];

let isScanning = false;
let currentScore = 72;
let activeHistoryFilter = 'all';

// ===== Navigation =====
let viewStack = ['dashboard-screen'];

const BOTTOM_NAV_SCREENS = ['dashboard-screen', 'platforms-screen', 'analyze-screen', 'report-screen', 'settings-screen'];

function navigateTo(screenId) {
    const isBottomNav = BOTTOM_NAV_SCREENS.includes(screenId);
    if (isBottomNav) {
        viewStack = [screenId];
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.getElementById(screenId).classList.add('active');
        updateBottomNav(screenId);
        return;
    }
    document.getElementById(screenId).classList.add('active');
    viewStack.push(screenId);
}

function navigateBack() {
    if (viewStack.length > 1) {
        const topScreen = viewStack.pop();
        document.getElementById(topScreen).classList.remove('active');
        const current = viewStack[viewStack.length - 1];
        updateBottomNav(current);
    }
}

function updateBottomNav(activeScreen) {
    document.querySelectorAll('.bottom-nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.screen === activeScreen);
    });
}

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        document.getElementById('splash-screen').classList.remove('active');
        navigateTo('dashboard-screen');
        animateScoreRing(currentScore);
    }, 2000);

    renderThreatList('dashboard-threats', mockThreats.slice(0, 3));
    renderThreatList('history-threats', mockThreats);
    renderPlatformCards();
    renderTipsList();
    setupHistoryFilters();

    // Connect to AI backend (non-blocking)
    checkApiHealth();
});

// ===== AI API Health Check =====
async function checkApiHealth() {
    try {
        const resp = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        const data = await resp.json();
        isApiConnected = data.status === 'ok';
    } catch (_) {
        isApiConnected = false;
    }
    updateApiStatusBadge();

    if (isApiConnected) {
        // Start polling real-time threat stream every 8 seconds
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollRealTimeThreats, 8000);
        pollRealTimeThreats(); // Immediate first poll
    }
}

function updateApiStatusBadge() {
    const badge = document.getElementById('api-status-badge');
    if (!badge) return;
    if (isApiConnected) {
        badge.textContent = 'AI Active';
        badge.className = 'api-badge api-badge-active';
        badge.title = 'Connected to CyberGuard AI backend at ' + API_BASE;
    } else {
        badge.textContent = 'Offline Mode';
        badge.className = 'api-badge api-badge-offline';
        badge.title = 'Backend not running. Start api_server.py for AI-powered detection.';
    }
}

// ===== Real-Time Threat Stream Polling =====
async function pollRealTimeThreats() {
    if (!isApiConnected) return;
    try {
        const resp = await fetch(`${API_BASE}/stream/latest?limit=5`, {
            signal: AbortSignal.timeout(4000)
        });
        const data = await resp.json();
        const threats = data.threats || [];

        let newItems = 0;
        threats.forEach(t => {
            const id = t.timestamp + t.message_preview;
            if (knownStreamIds.has(id)) return;
            knownStreamIds.add(id);

            if (t.risk_level === 'Safe') return;

            // Convert API result to the UI's threat format and prepend to mock list
            const newThreat = apiResponseToThreat(t);
            mockThreats.unshift(newThreat);
            newItems++;
        });

        if (newItems > 0) {
            // Refresh the visible list
            renderThreatList('dashboard-threats', mockThreats.slice(0, 3));
            renderThreatList('history-threats', mockThreats);
            renderPlatformCards();
            // Brief pulse on the dashboard recent threats header
            const header = document.querySelector('.recent-threats-header h3');
            if (header) {
                header.style.transition = 'color 0.3s';
                header.style.color = '#3B8BFF';
                setTimeout(() => { header.style.color = ''; }, 1200);
            }
        }
    } catch (_) {
        // Stream poll failed silently (backend may have restarted)
        isApiConnected = false;
        updateApiStatusBadge();
        if (pollInterval) clearInterval(pollInterval);
    }
}

// Convert API /stream/latest item → internal threat object
function apiResponseToThreat(t) {
    const platformKey = (t.platform || 'sms').toLowerCase();
    const platform = Object.values(Platforms).find(p => p.id === platformKey) || Platforms.SMS;

    const levelMap = {
        'Threat': ThreatLevels.DANGER,
        'Suspicious': ThreatLevels.SUSPICIOUS,
        'Safe': ThreatLevels.SAFE,
    };
    const level = levelMap[t.risk_level] || ThreatLevels.SUSPICIOUS;

    return {
        id: `ai-${Date.now()}-${Math.random()}`,
        platform,
        source: `${platform.label}: AI Detected`,
        contentPreview: t.message_preview || '(no preview)',
        level,
        timestamp: new Date(t.timestamp || Date.now()),
        details: `AI Model: ${t.model_used || 'ML Classifier'}. Confidence: ${(t.confidence * 100).toFixed(1)}%. This message was flagged by the real-time stream analyzer.`,
        tags: [t.risk_level, 'AI Detected', platform.label],
    };
}


// ===== Score Ring =====
function animateScoreRing(score) {
    const ring = document.getElementById('score-ring-fill');
    if (!ring) return;
    const circumference = 2 * Math.PI * 45;
    ring.style.strokeDasharray = circumference;
    ring.style.strokeDashoffset = circumference;

    let color = '#00E676';
    if (score < 50) color = '#FF1744';
    else if (score < 75) color = '#FFD600';
    ring.style.stroke = color;
    document.getElementById('score-value').style.color = color;

    setTimeout(() => {
        const offset = circumference - (score / 100) * circumference;
        ring.style.strokeDashoffset = offset;
    }, 100);
}

function updateScore(score) {
    currentScore = score;
    document.getElementById('score-value').textContent = score;
    animateScoreRing(score);
}

// ===== Render Functions =====
function getPlatformIcon(threat) {
    return threat.platform ? threat.platform.icon : 'link';
}

function renderThreatList(containerId, threats) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    if (threats.length === 0) {
        container.innerHTML = '<div class="empty-state"><span class="material-icons-round">check_circle</span><p>No threats found</p></div>';
        return;
    }

    threats.forEach(threat => {
        const dateStr = threat.timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        const item = document.createElement('div');
        item.className = 'threat-item';
        item.onclick = () => openAlert(threat);

        const platform = threat.platform || { icon: 'security', color: '#0052FF', bg: 'rgba(0,82,255,0.15)', label: 'System' };
        const tagsHTML = (threat.tags || []).slice(0, 2).map(t => `<span class="threat-tag">${t}</span>`).join('');

        item.innerHTML = `
            <div class="threat-icon-wrapper" style="background:${platform.bg}; color:${platform.color}">
                <span class="material-icons-round">${platform.icon}</span>
            </div>
            <div class="threat-info">
                <div class="threat-source-row">
                    <span class="threat-source">${threat.source}</span>
                    <span class="platform-badge" style="background:${platform.bg}; color:${platform.color}">${platform.label}</span>
                </div>
                <div class="threat-preview">${threat.contentPreview}</div>
                <div class="threat-tags">${tagsHTML}</div>
            </div>
            <div class="threat-meta">
                <div class="threat-date">${dateStr}</div>
                <div class="threat-level ${threat.level.color}">${threat.level.name}</div>
            </div>
        `;
        container.appendChild(item);
    });
}

function renderPlatformCards() {
    const container = document.getElementById('platform-cards');
    if (!container) return;
    container.innerHTML = '';

    const platformList = [Platforms.WHATSAPP, Platforms.INSTAGRAM, Platforms.TELEGRAM, Platforms.SMS, Platforms.EMAIL, Platforms.APP, Platforms.NETWORK];

    platformList.forEach(p => {
        const threats = mockThreats.filter(t => t.platform && t.platform.id === p.id);
        const dangerCount = threats.filter(t => t.level === ThreatLevels.DANGER).length;
        const warnCount = threats.filter(t => t.level === ThreatLevels.SUSPICIOUS).length;

        let riskLabel = 'SAFE';
        let riskClass = 'safe';
        if (dangerCount > 0) { riskLabel = 'HIGH RISK'; riskClass = 'danger'; }
        else if (warnCount > 0) { riskLabel = 'CAUTION'; riskClass = 'warning'; }

        const card = document.createElement('div');
        card.className = 'platform-card';
        card.onclick = () => {
            activeHistoryFilter = p.id;
            navigateTo('history-screen');
            applyHistoryFilter(p.id);
            // update tab UI
            document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
            const tab = document.querySelector(`.filter-tab[data-filter="${p.id}"]`);
            if (tab) tab.classList.add('active');
        };

        card.innerHTML = `
            <div class="platform-card-icon" style="background:${p.bg}; color:${p.color}">
                <span class="material-icons-round">${p.icon}</span>
            </div>
            <div class="platform-card-name">${p.label}</div>
            <div class="platform-card-count">${threats.length} threat${threats.length !== 1 ? 's' : ''}</div>
            <div class="platform-card-risk ${riskClass}">${riskLabel}</div>
        `;
        container.appendChild(card);
    });
}

function renderTipsList() {
    const container = document.getElementById('tips-list');
    if (!container) return;
    container.innerHTML = '';
    mockTips.forEach(tip => {
        const item = document.createElement('div');
        item.className = 'tip-card';
        item.innerHTML = `
            <div class="tip-header">
                <span class="material-icons-round tip-icon">${tip.icon}</span>
                <div>
                    <div class="tip-platform-badge">${tip.platform}</div>
                    <span class="tip-title">${tip.title}</span>
                </div>
            </div>
            <div class="tip-desc">${tip.description}</div>
        `;
        container.appendChild(item);
    });
}

// ===== History Filters =====
function setupHistoryFilters() {
    document.querySelectorAll('.filter-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            applyHistoryFilter(tab.dataset.filter);
        });
    });
}

function applyHistoryFilter(filter) {
    activeHistoryFilter = filter;
    const filtered = filter === 'all'
        ? mockThreats
        : mockThreats.filter(t => t.platform && t.platform.id === filter);
    renderThreatList('history-threats', filtered);
}

// ===== Alert Screen =====
function openAlert(threat) {
    const platform = threat.platform || { icon: 'security', color: '#0052FF', bg: 'rgba(0,82,255,0.15)', label: 'System' };

    document.getElementById('alert-icon').innerText = threat.level.icon;
    document.getElementById('alert-icon').className = `material-icons-round alert-main-icon ${threat.level.color}`;
    document.getElementById('alert-title').innerText = `${threat.level.name} DETECTED`;
    document.getElementById('alert-title').className = `alert-main-title ${threat.level.color}`;
    document.getElementById('alert-source').innerText = threat.source;
    document.getElementById('alert-platform-badge').innerText = platform.label;
    document.getElementById('alert-platform-badge').style.cssText = `background:${platform.bg}; color:${platform.color}`;

    const dateStr = threat.timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    document.getElementById('alert-date').innerText = dateStr;
    document.getElementById('alert-analysis').innerText = threat.details;
    document.getElementById('alert-analysis').className = `detail-value text-${threat.level.color}`;
    document.getElementById('alert-preview').innerText = threat.contentPreview;

    // Tags
    const tagsContainer = document.getElementById('alert-tags');
    tagsContainer.innerHTML = (threat.tags || []).map(t => `<span class="alert-tag">${t}</span>`).join('');

    navigateTo('alert-screen');
}

// ===== Scan =====
function startScan() {
    if (isScanning) return;
    isScanning = true;

    // Animate the score ring section as a scan indicator
    const ringWrapper = document.querySelector('.score-ring-wrapper');
    if (ringWrapper) ringWrapper.classList.add('scanning');

    // Update status card to show scanning state
    document.getElementById('status-card').innerHTML = `
        <span class="material-icons-round status-icon" style="color:var(--cyber-blue);animation:spin 1.5s linear infinite;">radar</span>
        <h2 class="status-title" style="color:var(--cyber-blue)">Scanning...</h2>
        <p class="status-message">Analyzing WhatsApp, SMS, Email & app permissions...</p>
    `;

    setTimeout(() => {
        if (ringWrapper) ringWrapper.classList.remove('scanning');
        isScanning = false;
        updateScore(38);
        document.getElementById('status-card').innerHTML = `
            <span class="material-icons-round status-icon danger">gpp_bad</span>
            <h2 class="status-title danger">High Risk</h2>
            <p class="status-message">3 critical threats detected across WhatsApp & Telegram. Immediate action required!</p>
        `;
        openAlert(mockThreats[0]);
    }, 2500);
}

function markSafe() {
    // Reset the block button before navigating back
    const blockBtn = document.getElementById('block-sender-btn');
    if (blockBtn) {
        blockBtn.innerHTML = '<span class="material-icons-round btn-icon">block</span> Delete & Block Sender';
        blockBtn.style.cssText = '';
        blockBtn.disabled = false;
    }
    navigateBack();
    setTimeout(() => {
        updateScore(95);
        document.getElementById('status-card').innerHTML = `
            <span class="material-icons-round status-icon safe">verified_user</span>
            <h2 class="status-title safe">Protected</h2>
            <p class="status-message">Threat resolved. Your device is now secure.</p>
        `;
    }, 300);
}

function blockSender() {
    const btn = document.getElementById('block-sender-btn');
    if (!btn || btn.disabled) return;
    btn.innerHTML = '<span class="material-icons-round btn-icon">check</span> Blocked & Deleted';
    btn.style.background = '#1A1A22';
    btn.style.border = '1px solid #FF1744';
    btn.style.color = '#FF1744';
    btn.disabled = true;

    // Navigate back after a short delay so user sees confirmation
    setTimeout(() => navigateBack(), 1200);
}

// ===== Link Analyzer (AI-powered with fallback) =====
const PHISHING_KEYWORDS = ['bit.ly', 'tinyurl', 'free', 'won', 'winner', 'urgent', 'click',
    'claim', 'bank', 'otp', 'verify', 'login', 'password', 'congratulations', 'prize',
    'limited', 'expire', 'account', 'suspended', 'confirm'];

function localAnalysis(input) {
    const lower = input.toLowerCase();
    let score = 0;
    const detectedFlags = [];
    PHISHING_KEYWORDS.forEach(kw => {
        if (lower.includes(kw)) { score += 12; detectedFlags.push(kw); }
    });
    if (/https?:\/\/bit\.ly|tinyurl\.com|t\.co\//.test(lower)) { score += 20; detectedFlags.push('Shortened URL'); }
    if (/\d{3,}/.test(lower)) score += 5;
    if (/[!]{2,}|₹|FREE|URGENT/i.test(input)) { score += 15; detectedFlags.push('Urgency / Pressure tactics'); }
    if (/whatsapp|telegram|instagram/i.test(lower)) score += 8;
    score = Math.min(score, 100);
    let verdict = 'SAFE';
    if (score >= 65) verdict = 'DANGER';
    else if (score >= 30) verdict = 'Suspicious';
    return { verdict, score, flags: [...new Set(detectedFlags)].slice(0, 5) };
}

async function analyzeLink() {
    const input = document.getElementById('analyze-input').value.trim();
    if (!input) {
        document.getElementById('analyze-input').style.borderColor = '#FF1744';
        setTimeout(() => document.getElementById('analyze-input').style.borderColor = '', 1000);
        return;
    }

    const resultSection = document.getElementById('analyze-result');
    const btn = document.getElementById('analyze-btn');
    btn.innerHTML = '<span class="material-icons-round spin-icon">sync</span> Analyzing...';
    btn.disabled = true;
    resultSection.style.display = 'none';

    let verdict, score, flags = [], modelUsed = 'Local Keyword Engine';

    try {
        if (isApiConnected) {
            // ── Real AI backend ──────────────────────────────────────
            const resp = await fetch(`${API_BASE}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: input, platform: 'manual' }),
                signal: AbortSignal.timeout(8000),
            });
            const data = await resp.json();

            const riskMap = { 'Threat': 'DANGER', 'Suspicious': 'Suspicious', 'Safe': 'SAFE' };
            verdict = riskMap[data.risk_level] || 'SAFE';
            score = Math.round(data.confidence * 100);
            modelUsed = data.model_used || 'AI Model';
        } else {
            // ── Local fallback ────────────────────────────────────────
            await new Promise(r => setTimeout(r, 1500));
            ({ verdict, score, flags } = localAnalysis(input));
        }
    } catch (_) {
        // API error – fall back silently
        isApiConnected = false;
        updateApiStatusBadge();
        await new Promise(r => setTimeout(r, 800));
        ({ verdict, score, flags } = localAnalysis(input));
    }

    // ── Render result ─────────────────────────────────────────────────
    const verdictMap = {
        'DANGER': { class: 'danger', icon: 'gpp_bad', msg: 'High probability of phishing or scam. Do NOT click or respond.' },
        'Suspicious': { class: 'warning', icon: 'warning', msg: 'Several red flags detected. Treat with extreme caution.' },
        'SAFE': { class: 'safe', icon: 'verified_user', msg: 'No major threats detected. Always stay cautious with unknown links.' },
    };
    const v = verdictMap[verdict] || verdictMap['SAFE'];

    const flagsHTML = flags.map(f => `<span class="flag-chip">${f}</span>`).join('');
    const modelBadge = `<span class="model-badge ${isApiConnected ? 'model-ai' : 'model-local'}">${modelUsed}</span>`;

    resultSection.style.display = 'block';
    resultSection.innerHTML = `
        <div class="analyze-result-card ${v.class}-border">
            <div class="result-verdict-row">
                <span class="material-icons-round result-icon ${v.class}">${v.icon}</span>
                <div>
                    <div class="result-verdict ${v.class}">${verdict === 'DANGER' ? 'DANGER' : verdict.toUpperCase()}</div>
                    <div class="result-score">Threat Score: <strong>${score}/100</strong></div>
                </div>
                ${modelBadge}
            </div>
            <p class="result-msg">${v.msg}</p>
            ${flags.length > 0 ? `<div class="result-flags-title">Red Flags Detected:</div><div class="result-flags">${flagsHTML}</div>` : ''}
            <div class="result-tip">💡 Tip: Always verify by calling the organization directly using their official website number.</div>
        </div>
    `;

    btn.innerHTML = '<span class="material-icons-round btn-icon">manage_search</span> Analyze';
    btn.disabled = false;
}

// ===== Report Crime =====
function submitReport() {
    const platform = document.getElementById('report-platform').value;
    const crimeType = document.getElementById('report-crime-type').value;
    const description = document.getElementById('report-description').value.trim();

    if (!platform || !crimeType || !description) {
        document.querySelectorAll('.report-form select, .report-form textarea').forEach(el => {
            if (!el.value.trim()) el.style.borderColor = '#FF1744';
        });
        setTimeout(() => {
            document.querySelectorAll('.report-form select, .report-form textarea').forEach(el => el.style.borderColor = '');
        }, 1500);
        return;
    }

    const btn = document.getElementById('submit-report-btn');
    btn.innerHTML = '<span class="material-icons-round spin-icon">sync</span> Submitting...';
    btn.disabled = true;

    setTimeout(() => {
        document.getElementById('report-form-area').style.display = 'none';
        document.getElementById('report-success').style.display = 'flex';
    }, 1800);
}

function resetReport() {
    document.getElementById('report-form-area').style.display = 'block';
    document.getElementById('report-success').style.display = 'none';
    document.getElementById('report-platform').value = '';
    document.getElementById('report-crime-type').value = '';
    document.getElementById('report-description').value = '';
    const btn = document.getElementById('submit-report-btn');
    btn.innerHTML = '<span class="material-icons-round btn-icon">send</span> Submit Report';
    btn.disabled = false;
}
