import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { Router, Toasts } from "./ui";
import "./styles.css";

try {
  const t = localStorage.getItem("fenrir-theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch {
  /* storage unavailable: follow the system theme */
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Router>
      <Toasts>
        <App />
      </Toasts>
    </Router>
  </StrictMode>,
);
