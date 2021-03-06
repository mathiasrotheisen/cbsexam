package cache;

import java.util.ArrayList;
import controllers.UserController;
import model.User;
import utils.Config;

public class UserCache {

    // List of products
    private ArrayList<User> users;

    // Time cache should live
    private long ttl;

    // Sets when the cache has been created
    private long created;

    public UserCache() {
        this.ttl = Config.getCacheTtl();
    }

    public ArrayList<User> getUsers(Boolean forceUpdate) {

        // If we wish to clear cache, we can set force update.
        // Otherwise we look at the age of the cache and figure out if we should update.
        // If the list is empty we also check for new products
        if (forceUpdate
                || ((this.created + this.ttl) <= (System.currentTimeMillis() / 1000L))
                || this.users == null) {

            // Get products from controller, since we wish to update.
            // Set products for the instance and set created timestamp
            this.users = UserController.getUsers();
            this.created = System.currentTimeMillis() / 1000L;
        }

        // Return the documents
        return this.users;
    }
}
