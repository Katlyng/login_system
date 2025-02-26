const usersRoles = [
    { user_id: 1, rol_id: 1 }, // Admin
    { user_id: 1, rol_id: 2 }, // Admin también es Editor
    { user_id: 2, rol_id: 4 }, // Juan es Usuario
    { user_id: 2, rol_id: 1 }, // Juan también es Moderador
  ];
  
  module.exports = usersRoles;
  