const express = require("express");
const {
  createProduct,
  getProducts,
  updateProduct,
  deleteProduct,
} = require("../controllers/productController");
const authenticateJWT = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/", authenticateJWT, createProduct);
router.get("/", authenticateJWT, getProducts);
router.put("/:id", authenticateJWT, updateProduct);
router.delete("/:id", authenticateJWT, deleteProduct);

module.exports = router;
