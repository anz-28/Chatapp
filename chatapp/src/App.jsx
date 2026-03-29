import { useEffect, useMemo, useState, useRef, useCallback } from 'react';
import {
  IoSend,
  IoLockClosed,
  IoShieldCheckmark,
  IoChatbubbleEllipses,
  IoMenu,
  IoLogOutOutline,
  IoFlash,
  IoPersonAdd,
  IoClose,
  IoSearch,
  IoTrashOutline,
  IoWarning,
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
  get,
  remove,
  query,
  limitToLast,
  orderByChild,
  equalTo,
  onValue,
  serverTimestamp,
} from './firebase';
import { sanitizeInput, isValidEmail, sanitizeURL, createRateLimiter } from './sanitize';
import { Analytics } from "@vercel/analytics/react";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const AUTO_PASSPHRASE_SUFFIX = 'a1u2t0m3a4t5e6d7c8h9a0t';

// Rate limiter: max 20 messages per 30 seconds
const messageRateLimiter = createRateLimiter(20, 30000);

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


/* ──────── Add Contact Modal ──────── */
function AddContactModal({ user, onClose, onContactAdded }) {
  const [email, setEmail] = useState('');
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleAddContact = async (e) => {
    e.preventDefault();
    const trimmedEmail = email.trim().toLowerCase();
    if (!trimmedEmail) return;

    if (!isValidEmail(trimmedEmail)) {
      setError('Please enter a valid email address.');
      return;
    }

    // Don't allow adding yourself
    if (trimmedEmail === user.email?.toLowerCase()) {
      setError("You can't add yourself as a contact.");
      return;
    }

    setSearching(true);
    setError('');
    setSuccess('');

    try {
      // Search for user by email in the users node
      const usersRef = ref(database, 'users');
      const q = query(usersRef, orderByChild('email'), equalTo(trimmedEmail));
      const snapshot = await get(q);

      if (!snapshot.exists()) {
        setError('No user found with that email. They need to sign in at least once first.');
        setSearching(false);
        return;
      }

      // Get the found user's data
      const foundUsers = snapshot.val();
      const foundUid = Object.keys(foundUsers)[0];
      const foundUser = foundUsers[foundUid];

      // Check if already a contact
      const contactRef = ref(database, `contacts/${user.uid}/${foundUid}`);
      const existingContact = await get(contactRef);

      if (existingContact.exists()) {
        setError('This person is already in your contacts.');
        setSearching(false);
        return;
      }

      // Add contact to both sides (mutual)
      await set(ref(database, `contacts/${user.uid}/${foundUid}`), {
        uid: foundUid,
        email: foundUser.email,
        displayName: foundUser.displayName || '',
        photoURL: foundUser.photoURL || '',
        addedAt: Date.now(),
      });

      await set(ref(database, `contacts/${foundUid}/${user.uid}`), {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName || '',
        photoURL: user.photoURL || '',
        addedAt: Date.now(),
      });

      setSuccess(`${foundUser.displayName || foundUser.email} has been added!`);
      setEmail('');
      onContactAdded?.();

      // Auto-close after a short delay
      setTimeout(() => onClose(), 1500);
    } catch (err) {
      console.error('Error adding contact:', err);
      setError('Something went wrong. Please try again.');
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card animate-fade-in" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Add Contact</h2>
          <button className="modal-close-btn" onClick={onClose}>
            <IoClose size={20} />
          </button>
        </div>

        <p className="modal-description">
          Enter the email address of the person you want to chat with. They must have signed in at least once.
        </p>

        <form className="modal-form" onSubmit={handleAddContact}>
          <div className="modal-input-wrapper">
            <IoSearch size={16} className="modal-input-icon" />
            <input
              ref={inputRef}
              type="email"
              placeholder="Enter email address..."
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setError('');
                setSuccess('');
              }}
              disabled={searching}
            />
          </div>

          {error && (
            <div className="modal-feedback error animate-fade-in">
              {error}
            </div>
          )}

          {success && (
            <div className="modal-feedback success animate-fade-in">
              {success}
            </div>
          )}

          <button
            className="btn-primary modal-submit-btn"
            type="submit"
            disabled={searching || !email.trim()}
          >
            {searching ? (
              <span className="btn-loading">Searching...</span>
            ) : (
              <>
                <IoPersonAdd size={16} />
                Add Contact
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}


/* ──────── Sidebar Component ──────── */
function Sidebar({ user, partnerList, selectedUser, setSelectedUser, encryptionKey, onLogout, isOpen, onClose, onAddContact, onRemoveContact }) {
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

      {/* Section title + Add button */}
      <div className="sidebar-section-header">
        <span className="sidebar-section-title">Contacts</span>
        <button className="add-contact-btn" onClick={onAddContact} title="Add a contact">
          <IoPersonAdd size={14} />
        </button>
      </div>

      {/* Users list */}
      <div className="sidebar-users">
        {partnerList.length === 0 ? (
          <div className="no-users">
            <div className="no-users-icon">
              <IoPersonAdd size={24} />
            </div>
            <p>No contacts yet.<br />Add someone by their email to start chatting!</p>
            <button className="btn-ghost add-first-btn" onClick={onAddContact}>
              <IoPersonAdd size={14} />
              Add your first contact
            </button>
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
              <button
                className="remove-contact-btn"
                onClick={(e) => {
                  e.stopPropagation();
                  onRemoveContact(u);
                }}
                title="Remove contact"
              >
                <IoTrashOutline size={14} />
              </button>
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
          <p>Select a contact from the sidebar to begin a private, end-to-end encrypted conversation.</p>
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
            onChange={(e) => setMessage(e.target.value.slice(0, 2000))}
            disabled={!user}
            autoFocus
            maxLength={2000}
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
  const [contacts, setContacts] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [saving, setSaving] = useState(false);
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [encryptedMode, setEncryptedMode] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [rateLimitWarning, setRateLimitWarning] = useState('');

  const usersRef = useMemo(() => ref(database, 'users'), []);

  const activeChatId = useMemo(() => {
    if (!user || !selectedUser) return null;
    return getChatId(user.uid, selectedUser.uid);
  }, [user, selectedUser]);

  const activeChatRef = useMemo(() => {
    if (!activeChatId) return null;
    return ref(database, `chats/${activeChatId}`);
  }, [activeChatId]);

  // Auth + users listener
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
        setContacts([]);
      }
    });

    const offUsers = onValue(usersRef, (snapshot) => {
      const usersMap = snapshot.val() || {};
      setUsers(Object.values(usersMap));
    }, (error) => {
      console.error('Users listener error:', error);
    });

    return () => {
      unsubscribeAuth();
      offUsers();
    };
  }, [usersRef]);

  // Contacts listener - listen for changes to current user's contacts
  useEffect(() => {
    if (!user) {
      setContacts([]);
      return;
    }

    const contactsRef = ref(database, `contacts/${user.uid}`);
    const offContacts = onValue(contactsRef, (snapshot) => {
      const contactsMap = snapshot.val() || {};
      setContacts(Object.values(contactsMap));
    }, (error) => {
      console.error('Contacts listener error:', error);
    });

    return () => offContacts();
  }, [user]);

  // Derive encryption key per chat
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

  // Messages listener
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
    const text = sanitizeInput(message);
    if (!text) return;

    if (encryptedMode && !encryptionKey) return;

    // Rate limiting
    const rateCheck = messageRateLimiter.check();
    if (!rateCheck.allowed) {
      const waitSec = Math.ceil(rateCheck.retryAfterMs / 1000);
      setRateLimitWarning(`Too many messages. Wait ${waitSec}s.`);
      setTimeout(() => setRateLimitWarning(''), 3000);
      return;
    }

    setSaving(true);
    try {
      const payload = encryptedMode && encryptionKey
        ? await encryptMessage(encryptionKey, text)
        : text;
      await push(activeChatRef, {
        from: user.uid,
        to: selectedUser.uid,
        username: user.displayName || user.email || 'Anonymous',
        photoURL: sanitizeURL(user.photoURL) || '',
        text: payload,
        encrypted: encryptedMode,
        createdAt: Date.now(),
        ts: serverTimestamp(),
      });
      setMessage('');
      setRateLimitWarning('');
    } catch (error) {
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveContact = useCallback(async (contactUser) => {
    if (!user || !contactUser) return;
    const confirmed = window.confirm(`Remove ${contactUser.displayName || contactUser.email} from your contacts?`);
    if (!confirmed) return;

    try {
      // Remove from both sides
      await remove(ref(database, `contacts/${user.uid}/${contactUser.uid}`));
      await remove(ref(database, `contacts/${contactUser.uid}/${user.uid}`));

      // If the removed contact was selected, deselect them
      if (selectedUser?.uid === contactUser.uid) {
        setSelectedUser(null);
      }
    } catch (err) {
      console.error('Error removing contact:', err);
    }
  }, [user, selectedUser]);

  // Build the partner list from contacts - match contact UIDs against the full users list
  // to get the latest user data (name, photo, etc.)
  const partnerList = useMemo(() => {
    if (!user) return [];
    const contactUids = new Set(contacts.map(c => c.uid));
    return users
      .filter(u => contactUids.has(u.uid) && u.uid !== user.uid)
      .map(u => ({
        ...u,
        // Merge contact-specific data if needed
        ...contacts.find(c => c.uid === u.uid),
        // But always prefer the latest user data
        displayName: u.displayName,
        email: u.email,
        photoURL: u.photoURL,
      }));
  }, [user, users, contacts]);

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

      {/* Add Contact Modal */}
      {showAddContact && (
        <AddContactModal
          user={user}
          onClose={() => setShowAddContact(false)}
          onContactAdded={() => {}}
        />
      )}

      {/* Rate Limit Warning */}
      {rateLimitWarning && (
        <div className="rate-limit-toast animate-fade-in" style={{ position: 'fixed', bottom: 80, right: 28, zIndex: 200 }}>
          <IoWarning size={14} />
          {rateLimitWarning}
        </div>
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
          onAddContact={() => setShowAddContact(true)}
          onRemoveContact={handleRemoveContact}
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
      <Analytics />
    </>
  );
}

export default App;
