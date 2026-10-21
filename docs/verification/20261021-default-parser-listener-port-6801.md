# Parser Studio — listener port default for new drafts

The original legacy default has been retired. Every new parser draft begins at **6801**, consistently in the shared guided model, Auto Parser initial identity screen, backend inventory suggestion, generated CONF and package metadata. The port is editable immediately beside manufacturer, product and version at **Auto Parser → Add Logs**. The backend compiler receives the exact chosen draft port; no source listener is installed or activated by downloading a draft.

Existing projects, imported parser pairs and browser-local restored versions preserve their explicitly saved port, including historic nondefault ports; they are not silently migrated or overwritten. The port planner is advisory, not a reservation, and live sensor ingest or target import is not verified. Syslog selected ports must remain >=6800, and all supported ports 1024–65535.

Evidence gates: frontend draft default and backend-adapter tests, backend port-plan and compiled CONF tests, real localhost Chromium Auto Parser first-entry → source review → field mapping → DRAFT download and decoded CONF inspection at **6801** plus explicit override **6905**. All generated parser files remain DRAFT with `targetImportVerified:false`.
