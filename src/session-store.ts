import session from "express-session";
import { Query, Resource } from "@cloud-cli/store";
import { UserSession } from "./store.js";

class SessionStoreImpl extends session.Store {
  protected async findAll() {
    return await Resource.find(UserSession, new Query<UserSession>());
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
      await new UserSession({ sid }).remove();
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  async clear(callback) {
    const all = await this.findAll();
    for (const s of all) {
      s.remove();
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
      const model = new UserSession({ sid });
      const s = await model.find();
      callback(null, s ? s.session : null);
    } catch (error) {
      callback(error);
    }
  }

  async set(sid, session, callback) {
    try {
      const s = new UserSession({ sid, session });
      s.save();
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

const store: session.Store = new SessionStoreImpl();
export default store;
