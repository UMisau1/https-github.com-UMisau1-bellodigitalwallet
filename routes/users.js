
const express = require('express');
const router = express.Router();


// =====================================
// AUDIT LOG HELPER
// =====================================

async function writeAuditLog({
  userId,
  action,
  entityType = 'user',
  entityId = null,
  details = {}
}) {

  const { error } = await supabase
    .from('audit_logs')
    .insert({
      user_id: userId,
      action: action,
      entity_type: entityType,
      entity_id: entityId,
      details: details
    });

  if (error) {
    console.error('Audit Log Error:', error);
  }
}


const supabase = require('../config/supabase');

const {
  authenticate,
  authorize
} = require('../middleware/auth');


// =====================================
// GET ALL USERS
// SUPER ADMIN ONLY
// =====================================

router.get(
  '/',
  authenticate,
  authorize('super_admin'),
  async (req, res) => {
    try {
      const { data, error } =
        await supabase.auth.admin.listUsers({
          page: 1,
          perPage: 100
        });

      if (error) {
        console.error('List users error:', error.message);

        return res.status(500).json({
          success: false,
          message: 'Unable to retrieve users.'
        });
      }

      const authUsers = data.users || [];
      const userIds = authUsers.map(user => user.id);

      let profiles = [];

      if (userIds.length > 0) {
        const { data: profileData, error: profileError } =
          await supabase
            .from('profiles')
            .select('id, role, is_active')
            .in('id', userIds);

        if (profileError) {
          console.error(
            'User profiles error:',
            profileError.message
          );

          return res.status(500).json({
            success: false,
            message: 'Unable to retrieve user profiles.'
          });
        }

        profiles = profileData || [];
      }

      const users = authUsers.map(user => {
        const profile = profiles.find(
          item => item.id === user.id
        );

        return {
          id: user.id,
          email: user.email,
          created_at: user.created_at,
          last_sign_in_at: user.last_sign_in_at,
          role: profile ? profile.role : null,
          is_active: profile ? profile.is_active : false
        };
      });

      return res.json({
        success: true,
        total: users.length,
        users
      });

    } catch (error) {
      console.error('Users API error:', error.message);

      return res.status(500).json({
        success: false,
        message: 'An error occurred while retrieving users.'
      });
    }
  }
);


// =====================================
// CREATE NEW USER
// SUPER ADMIN ONLY
// =====================================

router.post(
  '/',
  authenticate,
  authorize('super_admin'),
  async (req, res) => {
    try {
      const { email, password, role } = req.body;

      const allowedRoles = [
        'super_admin',
        'finance_officer',
        'approver',
        'agent',
        'viewer'
      ];

      if (!email || !password || !role) {
        return res.status(400).json({
          success: false,
          message: 'Email, password and role are required.'
        });
      }

      if (
        typeof email !== 'string' ||
        typeof password !== 'string' ||
        !allowedRoles.includes(role)
      ) {
        return res.status(400).json({
          success: false,
          message: 'Invalid user information or role.'
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          success: false,
          message: 'Password must contain at least 8 characters.'
        });
      }

      const normalizedEmail = email.trim().toLowerCase();

      const { data, error } =
        await supabase.auth.admin.createUser({
          email: normalizedEmail,
          password,
          email_confirm: true
        });

      if (error) {
        return res.status(400).json({
          success: false,
          message: error.message
        });
      }

      const newUser = data.user;

      const { data: profile, error: profileError } =
        await supabase
          .from('profiles')
          .update({
            role,
            is_active: true
          })
          .eq('id', newUser.id)
          .select('id, role, is_active')
          .maybeSingle();

      if (profileError || !profile) {
        await supabase.auth.admin.deleteUser(newUser.id);

        console.error(
          'New user profile assignment error:',
          profileError?.message || 'Profile not found'
        );

        return res.status(500).json({
          success: false,
          message: 'User profile could not be created. Account creation was rolled back.'
        });
      }


      // RECORD USER CREATION IN AUDIT LOG
      await writeAuditLog({
        userId: req.user.id,
        action: 'USER_CREATED',
        entityType: 'user',
        entityId: newUser.id,
        details: {
          email: newUser.email,
          assigned_role: profile.role,
          account_status: 'active'
        }
      });

      return res.status(201).json({
        success: true,
        message: 'User created successfully.',
        user: {
          id: newUser.id,
          email: newUser.email,
          role: profile.role,
          is_active: profile.is_active
        }
      });

    } catch (error) {
      console.error('Create user error:', error.message);

      return res.status(500).json({
        success: false,
        message: 'An error occurred while creating the user.'
      });
    }
  }
);


// =====================================
// SUSPEND / ACTIVATE USER
// SUPER ADMIN ONLY
// =====================================

router.patch(
  '/:id/status',
  authenticate,
  authorize('super_admin'),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { is_active } = req.body;

      if (typeof is_active !== 'boolean') {
        return res.status(400).json({
          success: false,
          message: 'Account status must be true or false.'
        });
      }

      // Prevent Super Admin from suspending their own account
      if (id === req.user.id && is_active === false) {
        return res.status(403).json({
          success: false,
          message: 'You cannot suspend your own account.'
        });
      }

      // Confirm that the target user exists
      const { data: existingProfile, error: findError } =
        await supabase
          .from('profiles')
          .select('id, role, is_active')
          .eq('id', id)
          .maybeSingle();

      if (findError) {
        console.error('Find user error:', findError.message);

        return res.status(500).json({
          success: false,
          message: 'Unable to verify target user.'
        });
      }

      if (!existingProfile) {
        return res.status(404).json({
          success: false,
          message: 'User profile not found.'
        });
      }

      // Update account status
      const { data: updatedProfile, error: updateError } =
        await supabase
          .from('profiles')
          .update({ is_active })
          .eq('id', id)
          .select('id, role, is_active')
          .maybeSingle();

      if (updateError || !updatedProfile) {
        console.error(
          'Update user status error:',
          updateError?.message || 'Profile not updated'
        );

        return res.status(500).json({
          success: false,
          message: 'Unable to update user account status.'
        });
      }

      return res.json({
        success: true,
        message: is_active
          ? 'User account activated successfully.'
          : 'User account suspended successfully.',
        user: updatedProfile
      });

    } catch (error) {
      console.error('User status API error:', error.message);

      return res.status(500).json({
        success: false,
        message: 'An error occurred while updating user status.'
      });
    }
  }
);


// =====================================
// UPDATE USER ROLE
// SUPER ADMIN ONLY
// =====================================

router.patch(
  '/:id/role',
  authenticate,
  authorize('super_admin'),
  async (req, res) => {

    try {

      const userId = req.params.id;
      const { role } = req.body;

      const allowedRoles = [
        'super_admin',
        'finance_officer',
        'approver',
        'agent',
        'viewer'
      ];

      if (!userId || !allowedRoles.includes(role)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid user ID or role.'
        });
      }

      // Prevent Super Admin from changing their own role
      if (userId === req.user.id) {
        return res.status(403).json({
          success: false,
          message: 'You cannot change your own role.'
        });
      }

      // Find target user
      const { data: targetUser, error: targetError } =
        await supabase
          .from('profiles')
          .select('id, role, is_active')
          .eq('id', userId)
          .maybeSingle();

      if (targetError) {
        throw targetError;
      }

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'User profile not found.'
        });
      }

      // Protect the last active Super Admin
      if (
        targetUser.role === 'super_admin' &&
        targetUser.is_active === true &&
        role !== 'super_admin'
      ) {

        const { count, error: countError } = await supabase
          .from('profiles')
          .select('id', { count: 'exact', head: true })
          .eq('role', 'super_admin')
          .eq('is_active', true);

        if (countError) {
          throw countError;
        }

        if (count <= 1) {
          return res.status(403).json({
            success: false,
            message: 'The last active Super Admin cannot be demoted.'
          });
        }
      }

      // Update user role
      const { data: updatedUser, error: updateError } =
        await supabase
          .from('profiles')
          .update({ role })
          .eq('id', userId)
          .select('id, role, is_active')
          .single();

      if (updateError) {
        throw updateError;
      }


await writeAuditLog({
  userId: req.user.id,
  action: req.body.is_active
    ? 'USER_ACTIVATED'
    : 'USER_SUSPENDED',
  entityType: 'user',
  entityId: userId,
  details: {
    previous_status: targetUser.is_active
      ? 'active'
      : 'suspended',
    new_status: req.body.is_active
      ? 'active'
      : 'suspended'
  }
});

await writeAuditLog({
  userId: req.user.id,
  action: 'USER_ROLE_CHANGED',
  entityType: 'user',
  entityId: userId,
  details: {
    email: null,
    previous_role: targetUser.role,
    new_role: role
  }
});


      return res.status(200).json({
        success: true,
        message: 'User role updated successfully.',
        user: updatedUser
      });

    } catch (error) {

      console.error('Update User Role Error:', error);

      return res.status(500).json({
        success: false,
        message: 'Unable to update user role.'
      });
    }
  }
);


module.exports = router;
