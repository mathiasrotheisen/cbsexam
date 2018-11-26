package controllers;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import model.User;
import utils.Hashing;
import utils.Log;

public class UserController {

  private static DatabaseController dbCon;

  public UserController() {
    dbCon = new DatabaseController();
  }

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"),
                        rs.getLong("created_at"));

        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";

    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"),
                        rs.getLong("created_at"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }

  public static User createUser(User user) {

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it : FIXED
    int userID = dbCon.insert(
            "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
                    + user.getFirstname()
                    + "', '"
                    + user.getLastname()
                    + "', '"
                    + Hashing.shaWithSalt(user.getPassword())
                    + "', '"
                    + user.getEmail()
                    + "', "
                    + user.getCreatedTime()
                    + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else {
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }

  public static boolean delete(String token) {

    DecodedJWT jwt = null;
    try {
      jwt = JWT.decode(token);
    } catch (JWTDecodeException exception) {
      System.out.println(exception.getMessage());
      System.out.println(exception.getStackTrace());
    }

    int id = jwt.getClaim("userID").asInt();

    Log.writeLog(UserController.class.getName(), id, "deleting a user in the Database", 0);

    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Check of the user exists
    User user = UserController.getUser(id);

    // Returns true if the user exists and the user is deleted from the database
    return user != null && dbCon.deleteUpdate("DELETE FROM user WHERE id =" + id);
  }


  public static User getUserByEmail(String email) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build the query for DB
    String sql = "SELECT * FROM user where email='" + email + "'";

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {


        user = new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"),
                rs.getLong("created_at"));
        // return the create object


        Algorithm algorithm = Algorithm.HMAC256("cbsexam");
        String token = JWT.create().withClaim("userID", user.getId()).withClaim("exp", 3600).sign(algorithm);
        user.setToken(token);

        return user;
      } else {
        System.out.println("No User found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  public static User updateUser(User userInfo) {

    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    DecodedJWT jwt = null;
    try {
      jwt = JWT.decode(userInfo.getToken());
    } catch (JWTDecodeException exception) {
      System.out.println(exception.getMessage());
      System.out.println(exception.getStackTrace());
    }

    int id = jwt.getClaim("userID").asInt();

    User userToUpdate = getUser(id);

    if (userInfo.getFirstname() != null)
      userToUpdate.setFirstname(userInfo.getFirstname());

    if (userInfo.getLastname() != null)
      userToUpdate.setLastname(userInfo.getLastname());

    if (userInfo.getPassword() != null)
      userToUpdate.setPassword(Hashing.shaWithSalt(userInfo.getPassword()));

    if (userInfo.getEmail() != null)
      userToUpdate.setEmail(userInfo.getEmail());

    String sql = "UPDATE user set first_name = '" + userToUpdate.getFirstname() +
            "', last_name = '" + userToUpdate.getLastname() +
            "', password = '" + userToUpdate.getPassword() +
            "', email = '" + userToUpdate.getEmail() +
            "' WHERE id = " + userToUpdate.getId();


    if (dbCon.deleteUpdate(sql)) {
      return userToUpdate;
    }
    return null;
  }

}