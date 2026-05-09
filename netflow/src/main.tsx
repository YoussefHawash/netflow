import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./components/App";
import "./styles.css";

const container = document.getElementById("app");
if (!container) throw new Error("App root was not found");

createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
