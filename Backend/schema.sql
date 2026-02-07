-- Roles and users
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_id INT,
    nom VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB;

-- Sous-divisions and cycles
CREATE TABLE IF NOT EXISTS sous_divisions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cycles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    annee INT,
    actif BOOLEAN DEFAULT 1
) ENGINE=InnoDB;

-- Centres
CREATE TABLE IF NOT EXISTS centres (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(150),
    type ENUM('public','prive'),
    sous_division_id INT,
    adresse VARCHAR(255),
    capacite INT,
    statut_agrement VARCHAR(50),
    cycle_id INT,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sous_division_id) REFERENCES sous_divisions(id),
    FOREIGN KEY (cycle_id) REFERENCES cycles(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS centre_locations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    centre_id INT,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    FOREIGN KEY (centre_id) REFERENCES centres(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Filières
CREATE TABLE IF NOT EXISTS filieres (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS centre_filieres (
    centre_id INT,
    filiere_id INT,
    PRIMARY KEY (centre_id, filiere_id),
    FOREIGN KEY (centre_id) REFERENCES centres(id),
    FOREIGN KEY (filiere_id) REFERENCES filieres(id)
) ENGINE=InnoDB;

-- Equipements
CREATE TABLE IF NOT EXISTS equipements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS centre_equipements (
    centre_id INT,
    equipement_id INT,
    PRIMARY KEY (centre_id, equipement_id),
    FOREIGN KEY (centre_id) REFERENCES centres(id),
    FOREIGN KEY (equipement_id) REFERENCES equipements(id)
) ENGINE=InnoDB;

-- Personnel
CREATE TABLE IF NOT EXISTS personnel (
    id INT AUTO_INCREMENT PRIMARY KEY,
    centre_id INT,
    nombre INT,
    FOREIGN KEY (centre_id) REFERENCES centres(id)
) ENGINE=InnoDB;

-- Logs
CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;
