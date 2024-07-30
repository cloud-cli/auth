import session from "express-session";

const {
  SESSION_SECRET = "",
  SESSION_DOMAIN = "",
  SESSION_COOKIE_SAMESITE = "",
  SESSION_COOKIE_SECURE = ""
} = process.env;

const sessionOptions: session.SessionOptions = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
};

if (SESSION_DOMAIN) {
  const sameSite = SESSION_COOKIE_SAMESITE ? SESSION_COOKIE_SECURE as session.SessionOptions['cookie']['sameSite'] : false;
  const secure = !!SESSION_COOKIE_SECURE;

  sessionOptions.cookie = {
    domain: SESSION_DOMAIN,
    httpOnly: true,
    sameSite,
    secure,
  };
}

export default session(sessionOptions);
