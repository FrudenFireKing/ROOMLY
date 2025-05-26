import os
import io
import base64
from flask import Blueprint, request, render_template, jsonify
from diffusers import StableDiffusionPipeline
from deep_translator import GoogleTranslator
import torch
import uuid
from PIL import Image
from gigachat import GigaChat
from gigachat.models import Chat
import yagmail

ai_bp = Blueprint('ai', __name__, template_folder='templates')

# Инициализация переводчика
translator = GoogleTranslator(source='ru', target='en')

# Настройки Stable Diffusion
model_id = "stabilityai/stable-diffusion-2-1-base"
device = "cuda" if torch.cuda.is_available() else "cpu"

# Загрузка модели генерации изображений
pipe = StableDiffusionPipeline.from_pretrained(
    model_id,
    torch_dtype=torch.float16 if device == "cuda" else torch.float32,
    token=False
).to(device)

# Оптимизация для GPU
if device == "cuda":
    try:
        pipe.enable_xformers_memory_efficient_attention()
        if hasattr(torch, 'compile'):
            pipe.unet = torch.compile(pipe.unet, mode="reduce-overhead", fullgraph=True)
    except:
        pass

# Инициализация GigaChat
gigachat = GigaChat(
    credentials='MWE0ZmRjZjAtNzc3ZS00Y2IwLWExYjQtMWI4MTVkYzk5YTQ4OmI0MDgyNTE2LTEyMzktNDAyYi1iZGI1LTM3NmIyZDFhN2MyZg==',
    verify_ssl_certs=False
)

# Настройки email
EMAIL_ADDRESS = "aroomly@yandex.ru"
EMAIL_PASSWORD = "adminroomly123456789"
yag = yagmail.SMTP(EMAIL_ADDRESS, EMAIL_PASSWORD)

def extract_requirements(text):
    try:
        messages = [
            {
                "role": "user",
                "content": f"""Проанализируй текст и выдели ТОЛЬКО конкретные требования к переговорной комнате. 
                Отвечай строго в формате списка без пояснений. Пример:
                - стол на 6 человек
                - проектор
                - бронирование на среду с 14:00 до 16:00

                Текст: "{text}"
                """
            }
        ]

        response = gigachat.chat(
            Chat(
                messages=messages,
                temperature=0.7,
                max_tokens=1000
            )
        )
        return [line.strip() for line in response.choices[0].message.content.split('\n') if line.strip()]
    
    except Exception as e:
        print(f"Ошибка GigaChat: {str(e)}")
        return []

@ai_bp.route('/ai')
def index():
    return render_template('ai_index.html')

@ai_bp.route('/ai/generate', methods=['POST'])
def generate_image():
    description = request.form.get('description')
    if not description:
        return jsonify({'error': 'Описание не предоставлено'}), 400

    try:
        translated_description = translator.translate(description)
        prompt = f"Modern meeting room, {translated_description}, professional design, high quality, realistic"
        
        image = pipe(
            prompt,
            num_inference_steps=1,
            guidance_scale=7.5,
            width=512,
            height=512
        ).images[0]

        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return jsonify({
            'image': f'data:image/png;base64,{img_base64}',
            'status': 'Генерация завершена!'
        })

    except Exception as e:
        return jsonify({'error': f'Ошибка генерации: {str(e)}'}), 500

@ai_bp.route('/ai/analyze', methods=['POST'])
def analyze_text():
    user_input = request.form.get('user_input')
    if not user_input:
        return jsonify({'error': 'Текст не предоставлен'}), 400
    
    requirements = extract_requirements(user_input)
    return jsonify({'requirements': requirements})

@ai_bp.route('/submit', methods=['POST'])
def submit_request():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        email = data.get('email', 'pavelsysuew06@yandex.ru')
        image_data = data.get('image')
        requirements = data.get('requirements', [])

        if not image_data or not image_data.startswith('data:image/png;base64,'):
            return jsonify({'success': False, 'error': 'Invalid image data'}), 400

        # Сохраняем временное изображение
        image_bytes = base64.b64decode(image_data.split(",")[1])
        temp_image = "temp_meeting_room.png"
        with open(temp_image, "wb") as f:
            f.write(image_bytes)

        # Отправка письма
        body = "Требования к переговорной комнате:\n\n" + "\n".join(requirements)
        yag.send(
            to=email,
            subject="Заявка на переговорную комнату",
            contents=body,
            attachments=temp_image
        )

        # Удаляем временный файл
        os.remove(temp_image)

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@ai_bp.after_request
def add_security_headers(response):
    if request.path.startswith('/ai/'):
        # Особые правила для /ai/
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com https://code.jquery.com 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https://i.imgur.com https://sun9-55.userapi.com; "
            "connect-src 'self' http://127.0.0.1:5000; "
            "frame-src 'none'; "
        )
    else:
        # Стандартные правила для остальных страниц
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
        )

    response.headers['Content-Security-Policy'] = csp_policy
    return response