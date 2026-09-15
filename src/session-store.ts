import session from "express-session";
import { UserSession, json, rows, run } from './database.js';

class SessionStoreImpl extends session.Store {
  protected async findAll() {
    return rows<UserSession>('auth_session');
  }

  async all(callback) {
    try {
      const sessions = await this.findAll();
      callback(null, sessions);
    } catch (error) {
      callback(error);
    }
  }

  async destroy(sid, callback) {
    try {
      await run('DELETE FROM auth_session WHERE sid = ?', [sid]);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  async clear(callback) {
    const all = await this.findAll();
    for (const s of all) {
      await run('DELETE FROM auth_session WHERE sid = ?', [s.sid]);
    }

    callback(null);
  }

  async length(callback) {
    try {
      callback(null, (await this.findAll()).length);
    } catch (error) {
      callback(error);
    }
  }

  async get(sid, callback) {
    try {
      const s = (await rows<UserSession>('auth_session', 'sid = ?', [sid]))[0];
      callback(null, s ? s.session : null);
    } catch (error) {
      callback(null);
    }
  }

  async set(sid, session, callback) {
    try {
      await run('INSERT OR REPLACE INTO auth_session (sid, session) VALUES (?, ?)', [sid, json(session)]);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

const store: session.Store = new SessionStoreImpl();
export default store;
