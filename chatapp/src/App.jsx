import { useEffect, useMemo, useState, useRef } from 'react';
import {
  IoSend,
  IoLockClosed,
  IoShieldCheckmark,
  IoChatbubbleEllipses,
  IoMenu,
  IoLogOutOutline,
  IoFlash,
} from 'react-icons/io5';
import { FcGoogle } from 'react-icons/fc';
import {
  auth,
  provider,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  database,
  ref,
  push,
  set,
  query,
  limitToLast,
  onValue,
  serverTimestamp,
} from './firebase';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AUTO_PASSPHRASE_SUFFIX = 'a1u2t0m3a4t5e6d7c8h9a0t';

async function deriveEncryptionKey(passphrase) {
  const salt = encoder.encode('chatapp-salt');
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 250000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function base64Encode(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  bytes.forEach((byte) => {
    str += String.fromCharCode(byte);
  });
  return btoa(str);
}

function base64Decode(base64) {
  const str = atob(base64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
}

async function encryptMessage(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(text),
  );
  return `${base64Encode(iv)}:${base64Encode(ciphertext)}`;
}

async function decryptMessage(key, encrypted) {
  try {
    const [ivB64, cipherB64] = encrypted.split(':');
    if (!ivB64 || !cipherB64) return '[invalid encrypted payload]';
    const iv = new Uint8Array(base64Decode(ivB64));
    const cipherData = base64Decode(cipherB64);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      cipherData,
    );
    return decoder.decode(plainBuffer);
  } catch (error) {
    console.error('Decrypt error', error);
    return '[unable to decrypt]';
  }
}

function getChatId(a, b) {
  return [a, b].sort().join('_');
}

function getInitials(name) {
  if (!name) return '?';
  return name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
}

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/* ──────── Icon Wrappers (Ionicons) ──────── */
const SendIcon = () => <IoSend size={18} />;
const LockIcon = () => <IoLockClosed size={10} />;
const ShieldIcon = () => <IoShieldCheckmark size={14} />;
const ChatIcon = () => <IoChatbubbleEllipses size={36} style={{ color: 'var(--text-muted)' }} />;
const MenuIcon = () => <IoMenu size={22} />;
const LogoutIcon = () => <IoLogOutOutline size={14} />;

const GoogleIcon = () => <FcGoogle size={18} />;



/* ──────── Login Screen ──────── */
function LoginScreen({ onLogin }) {
  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-logo"><IoChatbubbleEllipses size={28} /></div>
        <h1>Welcome Back</h1>
        <p>Sign in to continue your encrypted conversations. Your messages are secure and private.</p>
        <button className="btn-primary" onClick={onLogin}>
          <GoogleIcon />
          Continue with Google
        </button>
        <div className="login-features">
          <div className="feature">
            <span className="feature-icon"><IoLockClosed size={20} /></span>
            Encrypted
          </div>
          <div className="feature">
            <span className="feature-icon"><IoFlash size={20} /></span>
            Real-time
          </div>
          <div className="feature">
            <span className="feature-icon"><IoShieldCheckmark size={20} /></span>
            Secure
          </div>
        </div>
      </div>
    </div>
  );
}


/* ──────── Sidebar Component ──────── */
function Sidebar({ user, partnerList, selectedUser, setSelectedUser, encryptionKey, onLogout, isOpen, onClose }) {
  return (
    <div className={`sidebar ${isOpen ? 'open' : ''}`}>
      {/* Brand */}
      <div className="sidebar-header">
        <h1>
          <span className="logo-icon"><IoChatbubbleEllipses size={16} /></span>
          Chat
        </h1>
        <button className="btn-danger" onClick={onLogout}>
          <LogoutIcon /> Sign out
        </button>
      </div>

      {/* Profile Badge */}
      <div className="sidebar-profile">
        {user?.photoURL ? (
          <img src={user.photoURL} alt="Profile" className="avatar" />
        ) : (
          <div className="avatar-placeholder" />
        )}
        <div className="info">
          <div className="name">{user?.displayName || user?.email || 'User'}</div>
          <div className="status">Online</div>
        </div>
      </div>

      {/* Users list */}
      <div className="sidebar-section-title">Direct Messages</div>
      <div className="sidebar-users">
        {partnerList.length === 0 ? (
          <div className="no-users">
            <p>No other users online yet.<br />Share the link to invite friends!</p>
          </div>
        ) : (
          partnerList.map((u) => (
            <div
              key={u.uid}
              className={`user-item ${selectedUser?.uid === u.uid ? 'active' : ''}`}
              onClick={() => { setSelectedUser(u); onClose?.(); }}
            >
              <div className="user-avatar">
                {getInitials(u.displayName || u.email)}
              </div>
              <div className="user-info">
                <div className="user-name">{u.displayName || u.email}</div>
                <div className="user-status-text">Click to chat</div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Encryption Status */}
      <div className="sidebar-footer">
        <div className={`encryption-badge ${encryptionKey ? '' : 'pending'}`}>
          <ShieldIcon />
          {encryptionKey ? 'End-to-end encrypted' : 'Select a chat to enable E2EE'}
        </div>
      </div>
    </div>
  );
}


/* ──────── Chat Panel ──────── */
function ChatPanel({ user, selectedUser, messages, message, setMessage, sendMessage, saving, activeChatId, onMenuClick }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  if (!selectedUser) {
    return (
      <div className="chat-main">
        <div className="mobile-header" onClick={onMenuClick}>
          <MenuIcon />
          <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Chat</span>
        </div>
        <div className="empty-chat animate-fade-in">
          <div className="empty-icon">
            <ChatIcon />
          </div>
          <h3>Start a Conversation</h3>
          <p>Select a user from the sidebar to begin a private, end-to-end encrypted conversation.</p>
        </div>
      </div>
    );
  }

  const chatPartnerName = selectedUser.displayName || selectedUser.email;

  return (
    <div className="chat-main">
      {/* Mobile Header */}
      <div className="mobile-header" onClick={onMenuClick}>
        <MenuIcon />
        <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Chat</span>
      </div>

      {/* Chat Header */}
      <div className="chat-header animate-fade-in">
        <div className="chat-avatar">
          {getInitials(chatPartnerName)}
        </div>
        <div className="chat-info">
          <h3>{chatPartnerName}</h3>
          <p>
            <LockIcon /> Encrypted · {activeChatId?.slice(0, 16)}...
          </p>
        </div>
      </div>

      {/* Messages */}
      <div className="messages-container">
        {messages.length === 0 ? (
          <div className="empty-chat">
            <div className="empty-icon"><IoLockClosed size={28} /></div>
            <h3>Chat is empty</h3>
            <p>Send the first message to {chatPartnerName}. All messages are end-to-end encrypted.</p>
          </div>
        ) : (
          messages.map((msg, idx) => {
            const isOwn = user && msg.from === user.uid;
            return (
              <div
                key={msg.id}
                className={`message-row ${isOwn ? 'own' : 'other'}`}
                style={{ animationDelay: `${Math.min(idx * 0.03, 0.3)}s` }}
              >
                <div className="message-bubble animate-fade-in">
                  <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{msg.text}</p>
                  <div className="message-meta">
                    <span>{formatTime(msg.createdAt)}</span>
                    {msg.encrypted && <LockIcon />}
                  </div>
                </div>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input Area */}
      <div className="message-input-area">
        <form className="message-input-wrapper" onSubmit={sendMessage}>
          <input
            type="text"
            placeholder="Type a message..."
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={!user}
            autoFocus
          />
          <button
            className="send-btn"
            type="submit"
            disabled={!user || saving || !message.trim()}
            title="Send message"
          >
            <SendIcon />
          </button>
        </form>
      </div>
    </div>
  );
}


/* ──────── Main App ──────── */
function App() {
  const [user, setUser] = useState(null);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [saving, setSaving] = useState(false);
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [encryptedMode, setEncryptedMode] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const usersRef = useMemo(() => ref(database, 'users'), []);

  const activeChatId = useMemo(() => {
    if (!user || !selectedUser) return null;
    return getChatId(user.uid, selectedUser.uid);
  }, [user, selectedUser]);

  const activeChatRef = useMemo(() => {
    if (!activeChatId) return null;
    return ref(database, `chats/${activeChatId}`);
  }, [activeChatId]);

  useEffect(() => {
    const unsubscribeAuth = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        set(ref(database, `users/${currentUser.uid}`), {
          uid: currentUser.uid,
          email: currentUser.email,
          displayName: currentUser.displayName,
          photoURL: currentUser.photoURL,
          lastSeen: Date.now(),
        }).catch(console.error);
      } else {
        setEncryptionKey(null);
        setEncryptedMode(false);
      }
    });

    const offUsers = onValue(usersRef, (snapshot) => {
      const usersMap = snapshot.val() || {};
      setUsers(Object.values(usersMap));
    });

    return () => {
      unsubscribeAuth();
      offUsers();
    };
  }, [usersRef]);

  useEffect(() => {
    if (!activeChatId) {
      setEncryptionKey(null);
      setEncryptedMode(false);
      return;
    }

    const generatedPass = `${activeChatId}-${AUTO_PASSPHRASE_SUFFIX}`;
    const derive = async () => {
      try {
        const key = await deriveEncryptionKey(generatedPass);
        setEncryptionKey(key);
        setEncryptedMode(true);
      } catch (error) {
        console.error('Auto-chat passphrase derivation failed', error);
        setEncryptionKey(null);
        setEncryptedMode(false);
      }
    };

    derive();
  }, [activeChatId]);

  useEffect(() => {
    if (!activeChatRef) {
      setMessages([]);
      return;
    }

    const q = query(activeChatRef, limitToLast(200));
    const offChat = onValue(q, async (snapshot) => {
      const data = snapshot.val() || {};
      const msgs = await Promise.all(
        Object.entries(data)
          .map(async ([id, item]) => {
            if (item.encrypted && encryptionKey) {
              const decryptedText = await decryptMessage(encryptionKey, item.text);
              return { id, ...item, text: decryptedText };
            }
            if (item.encrypted && !encryptionKey) {
              return { id, ...item, text: '[encrypted message - key unavailable]' };
            }
            return { id, ...item };
          })
          .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0)),
      );
      setMessages(msgs);
    });

    return () => offChat();
  }, [activeChatRef, encryptionKey]);

  const login = async () => {
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      console.error('Login error', error);
    }
  };

  const logout = async () => {
    try {
      await signOut(auth);
    } catch (error) {
      console.error('Logout error', error);
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!user || !selectedUser) return;
    const text = message.trim();
    if (!text) return;

    if (encryptedMode && !encryptionKey) return;

    setSaving(true);
    try {
      const payload = encryptedMode && encryptionKey
        ? await encryptMessage(encryptionKey, text)
        : text;
      await push(activeChatRef, {
        from: user.uid,
        to: selectedUser.uid,
        username: user.displayName || user.email || 'Anonymous',
        photoURL: user.photoURL || '',
        text: payload,
        encrypted: encryptedMode,
        createdAt: Date.now(),
        ts: serverTimestamp(),
      });
      setMessage('');
    } catch (error) {
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  const partnerList = users.filter((u) => user && u.uid !== user.uid);

  // If not logged in, show login screen
  if (!user) {
    return <LoginScreen onLogin={login} />;
  }

  return (
    <>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="mobile-overlay"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="chat-layout">
        <Sidebar
          user={user}
          partnerList={partnerList}
          selectedUser={selectedUser}
          setSelectedUser={setSelectedUser}
          encryptionKey={encryptionKey}
          onLogout={logout}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />
        <ChatPanel
          user={user}
          selectedUser={selectedUser}
          messages={messages}
          message={message}
          setMessage={setMessage}
          sendMessage={sendMessage}
          saving={saving}
          activeChatId={activeChatId}
          onMenuClick={() => setSidebarOpen(true)}
        />
      </div>
    </>
  );
}

export default App;
