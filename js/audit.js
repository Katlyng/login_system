const { pool } = require("./connection.js");
const crypto = require("crypto");

const logEvent = async (userId, state, description, ip) => {
  try {
    const logId = crypto.randomUUID();

    const [result] = await pool.query(
      "INSERT INTO AUDIT_LOG (log_id, user_id, state, description, ip) VALUES (?, ?, ?, ?, ?)",
      [logId, userId || null, state, description, ip]
    );

    console.log(`Evento registrado en auditoría: ${state} - ${description}`);
    return result.affectedRows > 0;
  } catch (error) {
    console.error("Error al registrar evento en auditoría:", error);
    return false;
  }
};

// Constantes para los estados de auditoría
const AUDIT_STATES = {
  LOGIN_SUCCESS: "LOGIN_SUCCESS",
  LOGIN_FAILED: "LOGIN_FAILED",
  ACCOUNT_BLOCKED: "ACCOUNT_BLOCKED",
  ACCOUNT_UNLOCKED: "ACCOUNT_UNLOCKED",
  PASSWORD_RESET_REQUEST: "PASSWORD_RESET_REQUEST",
  PASSWORD_RESET_SUCCESS: "PASSWORD_RESET_SUCCESS",
  USER_REGISTERED: "USER_REGISTERED",
  LOGOUT: "LOGOUT",
  UNLOCK_TOKEN_REQUESTED: "UNLOCK_TOKEN_REQUESTED",
};

const getClientIp = (req) => {
  return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
};

const getUserAuditHistory = async (userId) => {
  try {
    const [logs] = await pool.query(
      "SELECT * FROM AUDIT_LOG WHERE user_id = ? ORDER BY date DESC",
      [userId]
    );
    return logs;
  } catch (error) {
    console.error("Error al obtener historial de auditoría:", error);
    return [];
  }
};

const getAllAuditLogs = async (limit = 100, offset = 0) => {
  try {
    const [logs] = await pool.query(
      "SELECT * FROM AUDIT_LOG ORDER BY date DESC LIMIT ? OFFSET ?",
      [limit, offset]
    );
    return logs;
  } catch (error) {
    console.error("Error al obtener registros de auditoría:", error);
    return [];
  }
};

module.exports = {
  logEvent,
  AUDIT_STATES,
  getClientIp,
  getUserAuditHistory,
  getAllAuditLogs,
};
