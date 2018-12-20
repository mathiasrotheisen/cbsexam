package com.cbsexam;

import cache.UserCache;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import controllers.UserController;
import java.util.ArrayList;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import model.Product;
import model.User;
import utils.Encryption;
import utils.Hashing;
import utils.Log;

@Path("user")
public class UserEndpoints {

  private static UserCache userCache = new UserCache();
  /**
   * @param idUser
   * @return Responses
   */
  @GET
  @Path("/{idUser}")
  public Response getUser(@PathParam("idUser") int idUser) {

    // Use the ID to get the user from the controller.
    User user = UserController.getUser(idUser);

    // TODO: Add Encryption to JSON : FIXED
    // Convert the user object to json in order to return the object
    String json = new Gson().toJson(user);

    // Add encryption to rawString
    json = Encryption.encryptDecryptXOR(json);

    // Return the user with the status code 200
    // TODO: What should happen if something breaks down?
    return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
  }

  /** @return Responses */
  @GET
  @Path("/")
  public Response getUsers() {

    // Write to log that we are here
    Log.writeLog(this.getClass().getName(), this, "Get all users", 0);

    // Get a list of users
    ArrayList<User> users = userCache.getUsers(false);

    // TODO: Add Encryption to JSON : FIXED
    // Transfer users to json in order to return it to the user
    String json = new Gson().toJson(users);

    // Add encryption to rawString
    json = Encryption.encryptDecryptXOR(json);

    // Return the users with the status code 200
    return Response.status(200).type(MediaType.APPLICATION_JSON).entity(json).build();
  }

  @POST
  @Path("/")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response createUser(String body) {

    // Read the json from body and transfer it to a user class
    User newUser = new Gson().fromJson(body, User.class);

    // Use the controller to add the user
    User createUser = UserController.createUser(newUser);

    // Get the user back with the added ID and return it to the user
    String json = new Gson().toJson(createUser);

    // Updates the cache
    userCache.getUsers(true);

    // Return the data to the user
    if (createUser != null) {
      // Return a response with status 200 and JSON as type
      return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
    } else {
      return Response.status(400).entity("Could not create user").build();
    }
  }

  // TODO: Make the system able to login users and assign them a token to use throughout the system. FIXED
  @POST
  @Path("/login")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response loginUser(String loginInfo) {

    User loginUser = new Gson().fromJson(loginInfo, User.class);

    User databaseUser = UserController.getUserByEmail(loginUser.getEmail());

    String json = new Gson().toJson(databaseUser);

    // && Hashing.shaWithSalt(loginUser.getPassword()).equals(databaseUser.getPassword())

    if (loginUser.getEmail().equals(databaseUser.getEmail()) && Hashing.shaWithSalt(loginUser.getPassword()).equals(databaseUser.getPassword())) {
      // Return a response with status 200 and JSON as type
      return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity(json).build();
    }
    return Response.status(400).entity("Could not login user. Check password / email").build();

  }

  @DELETE
  @Path("/delete/")
  // TODO: Make the system able to delete users: FIXED
  public Response deleteUser(String token) {

    //Method for deleting the user
    boolean successfulUserDeleted = UserController.delete(token);

    // Updates the cache
    userCache.getUsers(true);

    if (successfulUserDeleted){
      // Return a response with status 200 and JSON as type
      return Response.status(200).type(MediaType.APPLICATION_JSON_TYPE).entity("Deleted the user").build();
    }
    return Response.status(400).entity("There was a problem deleting the user").build();
  }

  // TODO: Make the system able to update users FIXED
  @POST
  @Path("/update/")
  public Response updateUser(String infoAndToken) {

    User userInfo = new Gson().fromJson(infoAndToken, User.class);

    User updatedUser = UserController.updateUser(userInfo);
    String json = new Gson().toJson(updatedUser);

    userCache.getUsers(true);

    if (updatedUser != null) {
      return Response.status(200).entity("Your new information" + json).build();
    }
    // Return a response with status 200 and JSON as type
    return Response.status(400).entity("The user to update was not found").build();
  }
}
