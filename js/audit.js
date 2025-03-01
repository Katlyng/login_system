const { pool } = require("./connection.js");
const crypto = require("crypto");

/**
 * Registra un evento en la tabla de auditoría
 * @param {string} userId - ID del usuario (null si no está autenticado)
 * @param {string} state - Estado o tipo de evento (LOGIN, LOGOUT, REGISTER, etc.)
 * @param {string} description - Descripción detallada del evento
 * @param {string} ip - Dirección IP desde donde se realizó la acción
 * @returns {Promise<boolean>} - True si se registró correctamente
 */
const logEvent = async (userId, state, description, ip) => {
    try {
        // Generar un ID único para el log
        const logId = crypto.randomUUID();

        // Insertar en la tabla de auditoría
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

// Constantes para los estados de auditoría (ayuda a mantener consistencia)
const AUDIT_STATES = {
    LOGIN_SUCCESS: "LOGIN_SUCCESS",
    LOGIN_FAILED: "LOGIN_FAILED",
    ACCOUNT_BLOCKED: "ACCOUNT_BLOCKED",
    ACCOUNT_UNLOCKED: "ACCOUNT_UNLOCKED",
    PASSWORD_RESET_REQUEST: "PASSWORD_RESET_REQUEST",
    PASSWORD_RESET_SUCCESS: "PASSWORD_RESET_SUCCESS",
    USER_REGISTERED: "USER_REGISTERED",
    LOGOUT: "LOGOUT",
};

// Función para obtener la dirección IP real (considerando proxies)
const getClientIp = (req) => {
    return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
};

// Función para consultar el historial de auditoría de un usuario específico
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

// Función para consultar todos los registros de auditoría (para administradores)
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
