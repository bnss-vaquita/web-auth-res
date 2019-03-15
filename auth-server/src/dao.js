
/* Data Access Objects
 *
 * At the moment, we simulate the DB with a MAP.
 * In the future, we want a real instance with a DB.
 *
 */

module.exports = class DAO {

    constructor(db){
        this.db = db;
    }

    get(id){
        return this.db.get(id);
    }

    has(id) {
        return this.db.has(id);
    }

    set(id, creds) {
        this.db.set(id, creds);
    }
}

