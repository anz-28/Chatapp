import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
} from 'firebase/auth';
import {
  getDatabase,
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
} from 'firebase/database';

// Firebase project configuration from Vite environment variables
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  databaseURL: import.meta.env.VITE_FIREBASE_DATABASE_URL || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const provider = new GoogleAuthProvider();
const database = getDatabase(app);

export {
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
};
