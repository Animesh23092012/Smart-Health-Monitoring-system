// ==========================================
// DEMO SENSOR DATA
// ==========================================

const demoButton = document.getElementById("demo-button");
const demoMessage = document.getElementById("demo-message");

if (demoButton) {

    demoButton.addEventListener("click", async function () {

        demoMessage.textContent = "Sending demo reading...";

        try {

            const response = await fetch("/api/sensor-data", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    heart_rate: 78,
                    systolic: 118,
                    diastolic: 76
                })
            });

            const result = await response.json();

            if (result.success) {

                demoMessage.textContent =
                    "✓ Demo reading saved successfully.";

            } else {

                demoMessage.textContent =
                    "✗ Unable to save demo reading.";

            }

        } catch (error) {

            demoMessage.textContent =
                "✗ Connection error.";

            console.error(error);
        }

    });

}