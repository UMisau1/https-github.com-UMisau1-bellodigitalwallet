
const supabase = require('../config/supabase');

// =====================================
// AUTHENTICATION MIDDLEWARE
// =====================================

async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
    }

    const token = authHeader.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication token is missing.'
      });
    }

    // Verify token with Supabase Auth
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired authentication session.'
      });
    }

    // Retrieve current user role and account status
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('id, role, is_active')
      .eq('id', data.user.id)
      .maybeSingle();

    if (profileError) {
      console.error('Authentication profile error:', profileError.message);

      return res.status(500).json({
        success: false,
        message: 'Unable to verify account permissions.'
      });
    }

    const allowedRoles = [
      'super_admin',
      'finance_officer',
      'approver',
      'agent',
      'viewer'
    ];

    if (
      !profile ||
      profile.is_active !== true ||
      !allowedRoles.includes(profile.role)
    ) {
      return res.status(403).json({
        success: false,
        message: 'Your account is inactive or unauthorized.'
      });
    }

    req.user = {
      id: data.user.id,
      email: data.user.email,
      role: profile.role
    };

    next();

  } catch (error) {
    console.error('Authentication middleware error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'An authentication error occurred.'
    });
  }
}

// =====================================
// ROLE AUTHORIZATION MIDDLEWARE
// =====================================

function authorize(...allowedRoles) {
  return function (req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to perform this action.'
      });
    }

    next();
  };
}

module.exports = {
  authenticate,
  authorize
};
