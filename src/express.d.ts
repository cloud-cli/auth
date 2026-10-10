declare global {
  namespace Express {
    interface Request {
      tokenUserId?: string;
      tokenAudience?: string;
      tokenScopes?: string[];
    }
  }
}

declare module 'express-session' {
  interface SessionData {
    qrLoginTransaction?: string;
  }
}

export {};
