"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.autorizarAdmin = autorizarAdmin;
function autorizarAdmin(req, res, next) {
    if (!req.user) {
        return res.sendStatus(401);
    }
    if (req.user.acesso !== "administrador") {
        return res.status(403).json({
            message: "Acesso negado. Apenas administradores."
        });
    }
    next();
}
