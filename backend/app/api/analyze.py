from fastapi import APIRouter
from app.models.analyze import AnalyzeRequest
from app.core.pipeline import run_pipeline_verbose

router = APIRouter()

# nhận log và gọi pipeline 

@router.post("/analyze")
def analyze_log(request: AnalyzeRequest):

    result = run_pipeline_verbose(request.log)

    return result