import session from "express-session";

const { SESSION_SECRET = '', SESSION_DOMAIN = '' } = process.env;

const sessionOptions: any = {
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  };
  
  if (SESSION_DOMAIN) {
    sessionOptions.cookie = {
      domain: SESSION_DOMAIN,
      httpOnly: true,
    };
  }
  
  

export default session(sessionOptions);