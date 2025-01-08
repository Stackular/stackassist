import { Octokit } from "@octokit/core";
import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = 3000;

// Use raw body parser for signature verification
app.use(bodyParser.raw({ type: 'application/json' }));

// Middleware to verify GitHub webhook signature
function verifyGitHubSignature(req, res, next) {
  const signature = req.headers['x-hub-signature-256'];
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  const hmac = crypto.createHmac('sha256', secret);
  const digest = `sha256=${hmac.update(req.body).digest('hex')}`;

  if (signature !== digest) {
    return res.status(401).send('Invalid signature');
  }

  next();
}

// Handle GitHub webhooks
app.post('/github/webhook', verifyGitHubSignature, (req, res) => {
  const event = req.headers['x-github-event'];
  const payload = JSON.parse(req.body);
  console.log('GitHub Event:', req.headers['x-github-event']);
  console.log('Payload:', JSON.stringify(req.body, null, 2));
  if (event === 'push') {
    console.log('Push event received:', payload);
  } else if (event === 'pull_request') {
    console.log('Pull request event received:', payload);
  }

  res.status(200).send('Event received');
});

// Route to handle GitHub OAuth callback
app.get('/github/callback', async (req, res) => {
  const code = req.query.code;
  const installationId = req.query.installation_id;

  console.log(`Received callback with code: ${code}, installation_id: ${installationId}`);

  try {
    // Exchange the code for an access token (if necessary)
    const response = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code: code,
      },
      {
        headers: {
          Accept: 'application/json',
        },
      }
    );

    const accessToken = response.data.access_token;
    console.log(`Access Token: ${accessToken}`);

    // Store the access token or use it as needed

    // Respond to the user or redirect them to the app page
    res.send('GitHub App successfully installed! You can close this page.');
  } catch (error) {
    console.error('Error during OAuth callback:', error.message);
    res.status(500).send('An error occurred during the GitHub OAuth callback.');
  }
});

// Generate JWT for GitHub App authentication
function generateJWT() {
  const privateKey = fs.readFileSync('./stackassist.2025-01-07.private-key.pem', 'utf8');
  const appId = process.env.GITHUB_APP_ID;

  const payload = {
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (10 * 60),
    iss: appId,
  };

  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Get installation access token
async function getInstallationAccessToken(installationId) {
  const jwtToken = generateJWT();

  try {
    const response = await axios.post(
      `https://api.github.com/app/installations/${installationId}/access_tokens`,
      {},
      {
        headers: {
          Authorization: `Bearer ${jwtToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      }
    );

    return response.data.token;
  } catch (error) {
    console.error('Error getting installation access token:', error.message);
    throw error;
  }
}

// Example of authenticated API request
async function makeAuthenticatedRequest() {
  const installationId = '59260928';

  try {
    const accessToken = await getInstallationAccessToken(installationId);
    const response = await axios.get('https://api.github.com/repos/YOUR_OWNER/YOUR_REPO/issues', {
      headers: {
        Authorization: `token ${accessToken}`,
        Accept: 'application/vnd.github.v3+json',
      },
    });

    console.log(response.data);
  } catch (error) {
    console.error('Error making authenticated request:', error.message);
  }
}

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://klaim.tplinkdns.com:${port}`);
});
