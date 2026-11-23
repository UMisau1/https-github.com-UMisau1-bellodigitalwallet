
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const router = express.Router();

// Separate client for user authentication
const authClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

// Separate client for privileged database operations
const adminClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

router.post('/login', async (req, res) => {
  try {
    const { email, password, accountType } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required.'
      });
    }

    // Authenticate user
    const { data, error } = await authClient.auth.signInWithPassword({
      email: email.trim().toLowerCase(),
      password
    });

    if (error || !data.user || !data.session) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    // Read profile using the separate admin client
    const { data: profile, error: profileError } = await adminClient
      .from('profiles')
      .select('id, role, is_active')
      .eq('id', data.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('Profile lookup error:', profileError.message);

      return res.status(500).json({
        success: false,
        message: 'Unable to verify user account.'
      });
    }

    if (!profile) {
      return res.status(403).json({
        success: false,
        message: 'User profile not found. Contact the administrator.'
      });
    }

    if (profile.is_active !== true) {
      return res.status(403).json({
        success: false,
        message: 'This account is inactive.'
      });
    }

    const allowedRoles = [
      'super_admin',
      'finance_officer',
      'approver',
      'agent',
      'viewer'
    ];

    if (!allowedRoles.includes(profile.role)) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized account role.'
      });
    }

    const roleMap = {
      'Super Administrator': 'super_admin',
      'Finance Officer': 'finance_officer',
      'Approver': 'approver',
      'Agent': 'agent',
      'Auditor / Viewer': 'viewer'
    };

    if (accountType && roleMap[accountType] !== profile.role) {
      return res.status(403).json({
        success: false,
        message: 'Selected account type does not match your assigned role.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      user: {
        id: data.user.id,
        email: data.user.email,
        role: profile.role
      }
    });

  } catch (error) {
    console.error('Login error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'An unexpected login error occurred.'
    });
  }
});

// =====================================
// VERIFY LOGGED-IN USER
// =====================================

router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authentication token is required.'
      });
    }

    const token = authHeader.split(' ')[1];

    const { data, error } = await authClient.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired login session.'
      });
    }

    const { data: profile, error: profileError } = await adminClient
      .from('profiles')
      .select('id, role, is_active')
      .eq('id', data.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('Profile verification error:', profileError.message);
      return res.status(500).json({
        success: false,
        message: 'Unable to verify user profile.'
      });
    }

    if (!profile || profile.is_active !== true) {
      return res.status(403).json({
        success: false,
        message: 'User account is missing or inactive.'
      });
    }

    const allowedRoles = [
      'super_admin',
      'finance_officer',
      'approver',
      'agent',
      'viewer'
    ];

    if (!allowedRoles.includes(profile.role)) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized account role.'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'User session verified.',
      user: {
        id: data.user.id,
        email: data.user.email,
        role: profile.role
      }
    });

  } catch (error) {
    console.error('Session verification error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'An unexpected verification error occurred.'
    });
  }
});

module.exports = router;
