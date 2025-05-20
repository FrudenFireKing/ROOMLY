import os
from flask import Flask, request, render_template, jsonify
from diffusers import StableDiffusionPipeline
from deep_translator import GoogleTranslator
import torch
import uuid
from PIL import Image
import io
import base64
from transformers import pipeline
import re

app = Flask(__name__)

# Инициализация модели Stable Diffusion
model_id = "stabilityai/stable-diffusion-2-1-base"  # Более легкая модель
device = "cuda" if torch.cuda.is_available() else "cpu"

# Загрузка модели генерации изображений
pipe = StableDiffusionPipeline.from_pretrained(
    model_id,
    torch_dtype=torch.float16 if device == "cuda" else torch.float32,
    use_auth_token=False
)
pipe = pipe.to(device)

# Оптимизация для GPU
if device == "cuda":
    try:
        pipe.enable_xformers_memory_efficient_attention()
        if hasattr(torch, 'compile'):
            pipe.unet = torch.compile(pipe.unet, mode="reduce-overhead", fullgraph=True)
    except:
        pass

# Папка для сохранения изображений
GENERATED_IMAGES_DIR = "generated_images"
os.makedirs(GENERATED_IMAGES_DIR, exist_ok=True)

# Переводчик
translator = GoogleTranslator(source='ru', target='en')

# Инициализация модели для анализа текста
nlp = pipeline("ner", model="distilbert-base-uncased", tokenizer="distilbert-base-uncased")

# Функция для извлечения требований
def extract_requirements(text):
    sentences = re.split(r'[.!?]', text)
    requirements = []
    
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
            
        ner_results = nlp(sentence)
        
        if "стол" in sentence.lower():
            requirements.append("нужен круглый стол")
        if "стуль" in sentence.lower():
            match = re.search(r'\d+', sentence)
            if match:
                requirements.append(f"{match.group()} стульев")
        if "освещение" in sentence.lower():
            requirements.append("должно быть хорошее освещение")
        if "принтер" in sentence.lower():
            requirements.append("должен быть принтер")
        if "сканер" in sentence.lower():
            requirements.append("должен быть сканер")
        
        time_match = re.search(r'на\s+(\w+)\s+с\s+(\d+:\d+)\s+до\s+(\d+:\d+)', sentence, re.IGNORECASE)
        if time_match:
            day, start, end = time_match.groups()
            requirements.append(f"бронирование на {day} с {start} до {end}")
    
    return requirements

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_image():
    description = request.form.get('description')
    if not description:
        return jsonify({'error': 'Описание не предоставлено'}), 400

    try:
        translated_description = translator.translate(description)
    except Exception as e:
        return jsonify({'error': f'Ошибка перевода: {str(e)}'}), 500

    prompt = f"Modern meeting room, {translated_description}, professional design, high quality, realistic"

    try:
        image = pipe(
            prompt,
            num_inference_steps=1,  # Шаги генерацияя
            guidance_scale=7.5,
            width=512,
            height=512
        ).images[0]

        job_id = str(uuid.uuid4())
        img_path = os.path.join(GENERATED_IMAGES_DIR, f"{job_id}.png")
        image.save(img_path)

        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return jsonify({
            'image': f'data:image/png;base64,{img_base64}',
            'status': 'Генерация завершена!'
        })

    except Exception as e:
        return jsonify({'error': f'Ошибка генерации: {str(e)}'}), 500

@app.route('/analyze', methods=['POST'])
def analyze_text():
    user_input = request.form.get('user_input')
    if not user_input:
        return jsonify({'error': 'Текст не предоставлен'}), 400
    
    requirements = extract_requirements(user_input)
    return jsonify({'requirements': requirements})

if __name__ == '__main__':
    app.run(debug=True)