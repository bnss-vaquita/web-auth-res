const uuidv4 = require('uuid/v4');


/**
 * We do not automatically clean this data, and thus are exposed to
 * DOS-attack through a memory leak if an attacker gets
 * ahold of user credentials!
 */

class TFAManager {
    constructor() {
       this.store = new Map();
    }

    /**
     * Add a generated token
     */
    addToken(token) {
        const id = uuidv4();
        this.store.set(id, token);
        return id;
    }

    /**
     * Retrieves and deletes a token from the store
     */
    getToken(id) {
        const token = this.store.get(id);
        this.store.delete(id);
        return token;
    }
}

exports.manager = new TFAManager();
