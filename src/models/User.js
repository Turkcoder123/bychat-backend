// User model for database interactions
// This represents the user table structure and related methods

class User {
  constructor(db) {
    this.db = db;
  }

  // Create users table if it doesn't exist
  async createTable() {
    const query = `
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(20) UNIQUE,
        password VARCHAR(255),
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        display_name VARCHAR(100),
        avatar TEXT,
        bio TEXT,
        verified BOOLEAN DEFAULT false,
        email_verified_at TIMESTAMP,
        phone_verified_at TIMESTAMP,
        two_factor_enabled BOOLEAN DEFAULT false,
        two_factor_secret VARCHAR(32),
        temp_two_factor_secret VARCHAR(32),
        google_id VARCHAR(255) UNIQUE,
        facebook_id VARCHAR(255) UNIQUE,
        twitter_id VARCHAR(255) UNIQUE,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        verification_token VARCHAR(255),
        phone_verification_code VARCHAR(6),
        is_active BOOLEAN DEFAULT true,
        is_banned BOOLEAN DEFAULT false,
        ban_reason TEXT,
        ban_expires_at TIMESTAMP
      );
      
      -- Create indexes for better performance
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
      CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
      CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
      CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login);
      
      -- Trigger to update the updated_at column
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
      
      CREATE TRIGGER update_users_updated_at 
          BEFORE UPDATE ON users 
          FOR EACH ROW 
          EXECUTE FUNCTION update_updated_at_column();
    `;

    try {
      await this.db.query(query);
      console.log('Users table created successfully');
    } catch (error) {
      console.error('Error creating users table:', error);
      throw error;
    }
  }

  // Find user by ID
  async findById(id) {
    try {
      const result = await this.db.query(
        'SELECT id, email, phone, first_name, last_name, display_name, avatar, bio, verified, two_factor_enabled, last_login, created_at, updated_at, is_active, is_banned FROM users WHERE id = $1 AND is_active = true AND is_banned = false',
        [id]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by ID:', error);
      throw error;
    }
  }

  // Find user by email
  async findByEmail(email) {
    try {
      const result = await this.db.query(
        'SELECT id, email, phone, password, first_name, last_name, display_name, avatar, bio, verified, two_factor_enabled, two_factor_secret, last_login, created_at, updated_at, is_active, is_banned FROM users WHERE email = $1 AND is_active = true',
        [email]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by email:', error);
      throw error;
    }
  }

  // Find user by phone
  async findByPhone(phone) {
    try {
      const result = await this.db.query(
        'SELECT id, email, phone, password, first_name, last_name, display_name, avatar, bio, verified, two_factor_enabled, two_factor_secret, last_login, created_at, updated_at, is_active, is_banned FROM users WHERE phone = $1 AND is_active = true',
        [phone]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by phone:', error);
      throw error;
    }
  }

  // Find user by Google ID
  async findByGoogleId(googleId) {
    try {
      const result = await this.db.query(
        'SELECT id, email, phone, first_name, last_name, display_name, avatar, bio, verified, two_factor_enabled, last_login, created_at, updated_at, is_active, is_banned FROM users WHERE google_id = $1 AND is_active = true',
        [googleId]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error finding user by Google ID:', error);
      throw error;
    }
  }

  // Create a new user
  async create(userData) {
    try {
      const {
        email,
        phone,
        password,
        firstName,
        lastName,
        displayName,
        avatar,
        bio,
        verified = false,
        verificationToken,
        phoneVerificationCode,
        googleId
      } = userData;

      let query;
      let params;

      if (googleId) {
        // Create user with Google ID (no password)
        query = `
          INSERT INTO users (email, first_name, last_name, display_name, avatar, bio, verified, google_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
          RETURNING id, email, phone, first_name, last_name, display_name, avatar, bio, verified, created_at
        `;
        params = [email, firstName, lastName, displayName, avatar, bio, verified, googleId];
      } else if (email) {
        // Create user with email and password
        query = `
          INSERT INTO users (email, password, first_name, last_name, display_name, avatar, bio, verification_token, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
          RETURNING id, email, phone, first_name, last_name, display_name, avatar, bio, verified, created_at
        `;
        params = [email, password, firstName, lastName, displayName, avatar, bio, verificationToken];
      } else if (phone) {
        // Create user with phone and password
        query = `
          INSERT INTO users (phone, password, first_name, last_name, display_name, avatar, bio, phone_verification_code, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
          RETURNING id, email, phone, first_name, last_name, display_name, avatar, bio, verified, created_at
        `;
        params = [phone, password, firstName, lastName, displayName, avatar, bio, phoneVerificationCode];
      } else {
        throw new Error('Either email or phone must be provided');
      }

      const result = await this.db.query(query, params);
      return result.rows[0];
    } catch (error) {
      console.error('Error creating user:', error);
      throw error;
    }
  }

  // Update user
  async update(id, userData) {
    try {
      const fields = [];
      const values = [];
      let index = 1;

      for (const [key, value] of Object.entries(userData)) {
        if (value !== undefined) {
          fields.push(`${key} = $${index}`);
          values.push(value);
          index++;
        }
      }

      if (fields.length === 0) {
        throw new Error('No fields to update');
      }

      values.push(id); // Add ID for WHERE clause

      const query = `
        UPDATE users 
        SET ${fields.join(', ')}
        WHERE id = $${index} AND is_active = true
        RETURNING id, email, phone, first_name, last_name, display_name, avatar, bio, verified, two_factor_enabled, last_login, created_at, updated_at
      `;

      const result = await this.db.query(query, values);
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error updating user:', error);
      throw error;
    }
  }

  // Verify user email
  async verifyEmail(token) {
    try {
      const result = await this.db.query(
        `
        UPDATE users 
        SET verified = true, verification_token = NULL, email_verified_at = NOW()
        WHERE verification_token = $1
        RETURNING id, email, verified
        `,
        [token]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error verifying email:', error);
      throw error;
    }
  }

  // Verify user phone
  async verifyPhone(phone, code) {
    try {
      const result = await this.db.query(
        `
        UPDATE users 
        SET verified = true, phone_verification_code = NULL, phone_verified_at = NOW()
        WHERE phone = $1 AND phone_verification_code = $2
        RETURNING id, phone, verified
        `,
        [phone, code]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error verifying phone:', error);
      throw error;
    }
  }

  // Enable two-factor authentication
  async enableTwoFactor(id, secret) {
    try {
      const result = await this.db.query(
        `
        UPDATE users 
        SET two_factor_enabled = true, two_factor_secret = $1, temp_two_factor_secret = NULL
        WHERE id = $2
        RETURNING id, two_factor_enabled
        `,
        [secret, id]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error enabling two-factor authentication:', error);
      throw error;
    }
  }

  // Disable two-factor authentication
  async disableTwoFactor(id) {
    try {
      const result = await this.db.query(
        `
        UPDATE users 
        SET two_factor_enabled = false, two_factor_secret = NULL
        WHERE id = $1
        RETURNING id, two_factor_enabled
        `,
        [id]
      );
      return result.rows[0] || null;
    } catch (error) {
      console.error('Error disabling two-factor authentication:', error);
      throw error;
    }
  }

  // Update last login time
  async updateLastLogin(id) {
    try {
      await this.db.query(
        'UPDATE users SET last_login = NOW() WHERE id = $1',
        [id]
      );
    } catch (error) {
      console.error('Error updating last login:', error);
      throw error;
    }
  }

  // Check if user is banned
  async isBanned(id) {
    try {
      const result = await this.db.query(
        'SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = $1',
        [id]
      );
      const user = result.rows[0];
      
      if (!user) return { isBanned: true, reason: 'User not found' };
      
      // Check if ban has expired
      if (user.is_banned && user.ban_expires_at && new Date() > new Date(user.ban_expires_at)) {
        // Ban expired, remove it
        await this.db.query(
          'UPDATE users SET is_banned = false, ban_expires_at = NULL, ban_reason = NULL WHERE id = $1',
          [id]
        );
        return { isBanned: false };
      }
      
      if (user.is_banned) {
        return { isBanned: true, reason: user.ban_reason, expiresAt: user.ban_expires_at };
      }
      
      return { isBanned: false };
    } catch (error) {
      console.error('Error checking if user is banned:', error);
      throw error;
    }
  }

  // Ban a user
  async banUser(id, reason, expiresAt = null) {
    try {
      await this.db.query(
        'UPDATE users SET is_banned = true, ban_reason = $1, ban_expires_at = $2 WHERE id = $3',
        [reason, expiresAt, id]
      );
    } catch (error) {
      console.error('Error banning user:', error);
      throw error;
    }
  }

  // Unban a user
  async unbanUser(id) {
    try {
      await this.db.query(
        'UPDATE users SET is_banned = false, ban_reason = NULL, ban_expires_at = NULL WHERE id = $1',
        [id]
      );
    } catch (error) {
      console.error('Error unbanning user:', error);
      throw error;
    }
  }
}

module.exports = User;