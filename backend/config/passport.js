const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const OAuth2Strategy = require('passport-oauth2').Strategy;
const { 
  findUserByGoogleId, 
  createUserFromGoogle,
  findUserByDiscordId,
  createUserFromDiscord,
  findUserByGithubId,
  createUserFromGithub
} = require('../models/User');

// =============================================================================
// TODO 1: Configuration de la stratégie Google OAuth 2.0
// =============================================================================
// Instructions:
// 1. Importer GoogleStrategy depuis 'passport-google-oauth20'
// 2. Configurer passport.use() avec new GoogleStrategy()
// 3. Options à passer :
//    - clientID: process.env.GOOGLE_CLIENT_ID
//    - clientSecret: process.env.GOOGLE_CLIENT_SECRET
//    - callbackURL: process.env.GOOGLE_CALLBACK_URL
//    - passReqToCallback: true (pour accéder à req.app.locals.db)
// 4. Fonction callback async (req, accessToken, refreshToken, profile, done) :
//    a. Récupérer db depuis req.app.locals.db
//    b. Chercher l'utilisateur par googleId (profile.id) avec findUserByGoogleId()
//    c. Si l'utilisateur n'existe pas, le créer avec createUserFromGoogle()
//       - googleId: profile.id
//       - email: profile.emails[0].value
//       - name: profile.displayName
//       - picture: profile.photos[0].value
//    d. Appeler done(null, user) pour retourner l'utilisateur
//    e. En cas d'erreur, appeler done(error, null)
//
// Documentation : https://www.passportjs.org/packages/passport-google-oauth20/
// =============================================================================

// Configuration Google OAuth 2.0
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;
        
        // Chercher l'utilisateur par googleId
        let user = await findUserByGoogleId(db, profile.id);
        
        // Si l'utilisateur n'existe pas, le créer
        if (!user) {
          user = await createUserFromGoogle(db, {
            googleId: profile.id,
            email: profile.emails[0]?.value,
            name: profile.displayName,
            picture: profile.photos[0]?.value
          });
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// Configuration Discord OAuth 2.0 (stratégie générique)
passport.use(
  'discord',
  new OAuth2Strategy(
    {
      authorizationURL: 'https://discord.com/api/oauth2/authorize',
      tokenURL: 'https://discord.com/api/oauth2/token',
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;
        
        // Récupérer le profil Discord
        const response = await fetch('https://discord.com/api/users/@me', {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        const discordUser = await response.json();
        
        // Chercher l'utilisateur par discordId
        let user = await findUserByDiscordId(db, discordUser.id);
        
        // Si l'utilisateur n'existe pas, le créer
        if (!user) {
          user = await createUserFromDiscord(db, {
            discordId: discordUser.id,
            email: discordUser.email,
            username: discordUser.username,
            avatar: discordUser.avatar
          });
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// Configuration GitHub OAuth 2.0 (stratégie générique OAuth2)
passport.use(
  'github',
  new OAuth2Strategy(
    {
      authorizationURL: 'https://github.com/login/oauth/authorize',
      tokenURL: 'https://github.com/login/oauth/access_token',
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      passReqToCallback: true,
      headers: {
        'Accept': 'application/vnd.github.v3+json'
      }
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;
        
        // Récupérer le profil GitHub
        const response = await fetch('https://api.github.com/user', {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        const githubUser = await response.json();
        
        // Chercher l'utilisateur par githubId
        let user = await findUserByGithubId(db, githubUser.id);
        
        // Si l'utilisateur n'existe pas, le créer
        if (!user) {
          user = await createUserFromGithub(db, {
            githubId: githubUser.id,
            email: githubUser.email,
            username: githubUser.login,
            picture: githubUser.avatar_url
          });
        }
        
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// ⚠️ PAS de serializeUser/deserializeUser car on utilise JWT (stateless)
// Ces fonctions sont uniquement pour les sessions

module.exports = passport;
