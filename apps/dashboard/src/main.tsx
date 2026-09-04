// First, and deliberately so: this installs the Node globals circomlibjs needs
// before any module that reaches for them is evaluated.
import "./node-shims";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
