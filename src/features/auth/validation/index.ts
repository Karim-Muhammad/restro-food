import { body } from "express-validator";
import Validations from "../../../common/Validations";
import { customMessage } from "../../../common/helpers";
import UserModel from "../../user/model";
import { PASSWORD_REGEX } from "../../../common/constants";

class AuthValidations extends Validations {
  static instance: AuthValidations = null;

  constructor() {
    super();
  }

  public register() {
    return [
      body("username")
        .notEmpty()
        .withMessage(customMessage("`username` is required, should be string"))
        .bail()
        .isLength({ min: 3, max: 20 })
        .withMessage("`username` should be between 3 to 20 characters"),

      body("email")
        .isEmail()
        .withMessage("must enter valid email")
        .bail()
        .custom(async (email) => {
          return await this.isEmailTaken(email);
        })
        .withMessage("This email is already taken"),

      body("password")
        .matches(PASSWORD_REGEX)
        .withMessage(
          "should be strong password(uppercase, lowercase, number, special character, min 8 characters)"
        )
        .bail(),
      body("mobile").optional().isMobilePhone("ar-EG"),

      this.validate(),
    ];
  }

  public resetPassword() {
    return [
      body("password").matches(PASSWORD_REGEX).withMessage("Invalid Password"),
      body("password-confirmation")
        .custom((value, { req }) => {
          if (req.body.password !== value)
            throw Error("password and confirmation is not matched!");

          return true;
        })
        .withMessage("Password and Confirmation is not matched!"),

      this.validate(),
    ];
  }

  public changePassword() {
    return [
      body("old-password").notEmpty().withMessage("Old Password is required"),
      body("new-password")
        .notEmpty()
        .withMessage("New Password is required")
        .bail()
        .matches(PASSWORD_REGEX)
        .withMessage(
          "should be strong password(uppercase, lowercase, number, special character, min 8 characters)"
        ),
      body("new-password-confirmation")
        .notEmpty()
        .withMessage("New Password Confirmation is reuqired")
        .bail()
        .custom((value, { req }) => {
          if (req.body["new-password"] !== value)
            throw Error("new-password and confirmation is not matched!");

          return true;
        }),

      this.validate(),
    ];
  }

  public isEmailTaken(email: string) {
    return UserModel.findOne({ email }).then((document) => {
      console.log("Document", document);
      if (document) throw new Error("This email is invalid");
      return true;
    });
  }

  public static getInstance() {
    if (!this.instance) {
      this.instance = new AuthValidations();
    }

    return this.instance;
  }
}

export default AuthValidations;
