/** User class for message.ly */
const db = require(`../db`)
const bcrypt = require('bcrypt')
const { BCRYPT_WORK_FACTOR } = require(`../config`);
const ExpressError = require('../expressError');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({username, password, first_name, last_name, phone}) {
    try{
      const hashedPwd = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
      const timeStamp = new Date();

      const result = await db.query(`
        INSERT INTO users
          (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPwd, first_name, last_name, phone, timeStamp, timeStamp])

      return result.rows[0]
    }
    catch(err){
      throw new ExpressError(`User registration failed`, 400)
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try{
      const result = await db.query(`
        SELECT username, password FROM users
        WHERE username=$1`, [username]);
      return await bcrypt.compare(password, result.rows[0].password);
    }
    catch(err){
      throw new ExpressError(`User authentication failed`, 400)
    }
    // should handle for missing username,pwd?
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const timeStamp = new Date();

    try {
      const result = await db.query(`
        UPDATE users SET last_login_at=$2
        WHERE username=$1
        RETURNING username, last_login_at`,
        [username, timeStamp]);
      return result.rows[0]
    }
    catch(err){
      return new ExpressError(`Update login timestamp failed`, 400)
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    try{
      const result = await db.query(`
        SELECT username, first_name, last_name, phone
        FROM users`);
      return result.rows
    }
    catch(err){
      next(err);
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    try{
      const result = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users WHERE username=$1`, [username]);
      if (result.rows[0] === undefined){
        throw new ExpressError(`User not found`, 404)
      }
      return result.rows[0]
    }
    catch (err){
      next(e)
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    try{
      // check for valid user
      await User.get(username);

      // get messages for user
      const messageRes = await db.query(`
        SELECT
          m.id, m.to_username, m.body, m.sent_at, m.read_at,
          users.first_name, users.last_name, users.phone
        FROM messages AS m
        INNER JOIN users
        ON m.to_username = users.username
        WHERE from_username = $1`,
        [username])
      return messageRes.rows.map(m => ({
        id: m.id,
        to_user: {
          username: m.to_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at
      }))
    }
    catch(err){
      next(err);
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { const result = await db.query(
      `SELECT m.id, m.from_username, m.body, m.sent_at, m.read_at,
            users.first_name, users.last_name, users.phone
      FROM messages AS m
       JOIN users ON m.from_username = users.username
      WHERE to_username = $1`,
    [username]);
    return result.rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }
}


module.exports = User;
