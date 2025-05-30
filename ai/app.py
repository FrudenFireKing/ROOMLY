import os
import io
import base64
import json
from flask import Blueprint, request, render_template, jsonify
from diffusers import StableDiffusionPipeline
from deep_translator import GoogleTranslator
import torch
import uuid
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

@ai_bp.route('/generate', methods=['POST'])
def generate_image():
    description = request.form.get('description')
    if not description:
        return jsonify({'error': 'Описание не предоставлено'}), 400

    try:
        translated_description = translator.translate(description)
        prompt = f"Modern meeting room, {translated_description}, professional design, high quality, realistic"
        
        image = pipe(
            prompt,
            num_inference_steps=30,
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

@ai_bp.route('/analyze', methods=['POST'])
def analyze_text():
    user_input = request.form.get('user_input')
    if not user_input:
        return jsonify({'error': 'Текст не предоставлен'}), 400
    
    requirements = extract_requirements(user_input)
    return jsonify({'requirements': requirements})


@ai_bp.route('/submit', methods=['POST'])
def submit_request():
    try:
        # Проверяем наличие файла изображения
        if 'image' not in request.files:
            return jsonify({'success': False, 'error': 'No image provided'}), 400

        image_file = request.files['image']
        if image_file.filename == '':
            return jsonify({'success': False, 'error': 'No selected image'}), 400

        # Получаем остальные данные
        email = request.form.get('email', 'aroomly@yandex.ru')
        requirements = json.loads(request.form.get('requirements', '[]'))

        # Создаем уникальное имя файла
        temp_image = f"temp_meeting_room_{uuid.uuid4().hex}.png"
        image_file.save(temp_image)

        # Формируем тело письма
        body = f"""
        <h2>Новая заявка на переговорную комнату</h2>
        <h3>От: {email}</h3>
        <h3>Требования:</h3>
        <ul>
        {"".join(f"<li>{req}</li>" for req in requirements)}
        </ul>
        <p>Сгенерированное изображение прикреплено к письму.</p>
        """

        # Отправляем письмо
        yag.send(
            to='aroomly@yandex.ru',
            subject="Новая заявка на переговорную комнату",
            contents=body,
            attachments=temp_image,
            headers={"Content-Type": "text/html"}
        )

        return jsonify({
            'success': True,
            'message': 'Заявка успешно отправлена!'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        # Удаляем временный файл, если он существует
        if os.path.exists(temp_image):
            os.remove(temp_image)


@ai_bp.after_request
def add_security_headers(response):
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com https://code.jquery.com; "
        "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' http://localhost:5000; "
        "frame-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
    )

    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response