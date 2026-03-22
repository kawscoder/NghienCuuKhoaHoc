from fastapi import FastAPI, UploadFile, File, Form
from app.input.text_handler import analyze_text
from app.input.file_handler import analyze_file
from app.input.image_handler import analyze_image

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


app = FastAPI(
    title="DefLog AI",
    description="AI Log Analysis System",
    version="1.0"
) 

app.mount("/static", StaticFiles(directory="../frontend/src"), name="static")
app.mount("/assets", StaticFiles(directory="../frontend/src"), name="assets")

@app.get("/")
def root():
    return {"message": "DefLog API running"}

@app.get("/ui")
def ui():
    return FileResponse("../frontend/src/index.html")

# ---- TEXT INPUT ----
@app.post("/analyze/text")
def analyze_text_log(log: str = Form(...)):

    result = analyze_text(log)

    return result


# ---- FILE INPUT ----
@app.post("/analyze/file")
async def analyze_file_log(file: UploadFile = File(...)):

    file_location = f"temp_{file.filename}"

    with open(file_location, "wb") as f:
        f.write(await file.read())

    results = analyze_file(file_location)

    return {"results": results}


# ---- IMAGE INPUT ----
@app.post("/analyze/image")
async def analyze_image_log(file: UploadFile = File(...)):

    file_location = f"temp_{file.filename}"

    with open(file_location, "wb") as f:
        f.write(await file.read())

    results = analyze_image(file_location)

    return {"results": results}

from app.api.analyze import router  # đúng path file của anh

app.include_router(router)